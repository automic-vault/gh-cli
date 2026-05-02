# AGENTS.md

This is the GitHub CLI (`gh`), a command-line tool for interacting with GitHub. The module path is `github.com/cli/cli/v2`.

## Build, Test, and Lint

```bash
make                                       # Build (Unix) — outputs bin/gh
go run script/build.go                     # Build (Windows)
go test ./...                              # All unit tests
go test ./pkg/cmd/issue/list/... -run TestIssueList_nontty  # Single test
go test -tags acceptance ./acceptance      # Acceptance tests
make lint                                  # golangci-lint (same as CI)
```

**Before committing, ensure both tests and linter pass:**
```bash
go test ./...
make lint
```

## Architecture

Entry point: `cmd/gh/main.go` → `internal/ghcmd.Main()` → `pkg/cmd/root.NewCmdRoot()`.

Key packages:
- `pkg/cmd/<command>/<subcommand>/` — CLI command implementations
- `pkg/cmdutil/` — Factory, error types, flag helpers (`NilStringFlag`, `NilBoolFlag`, `StringEnumFlag`)
- `pkg/iostreams/` — I/O abstraction with TTY detection, color, pager
- `pkg/httpmock/` — HTTP mocking for tests
- `api/` — GitHub API client (GraphQL + REST)
- `internal/featuredetection/` — GitHub.com vs GHES capability detection
- `internal/tableprinter/` — Table output for list commands

## Command Structure

A command `gh foo bar` lives in `pkg/cmd/foo/bar/` with `bar.go`, `bar_test.go`, and optionally `http.go`/`http_test.go`.

### Canonical Examples

- **Command + tests**: `pkg/cmd/issue/list/list.go` and `list_test.go`
- **Factory wiring**: `pkg/cmd/factory/default.go`
- **Unit tests**: `internal/agents/detect_test.go`

### The Options + Factory Pattern

Every command follows this structure (see `pkg/cmd/issue/list/list.go`):

1. `Options` struct with `IO`, `HttpClient`, `Config`, `BaseRepo` + flags
2. `NewCmdFoo(f *cmdutil.Factory, runF func(*FooOptions) error)` constructor — `runF` is the test injection point
3. Separate `fooRun(opts)` function with the business logic

Key rules:
- Lazy-init `BaseRepo`, `Remotes`, `Branch` inside `RunE`, not the constructor
- Commands register in `pkg/cmd/root/root.go`; subcommand groups use `cmdutil.AddGroup()`

### Command Examples and Help Text

Use `heredoc.Doc` for examples with `#` comment lines and `$ ` command prefixes:
```go
Example: heredoc.Doc(`
    # Do the thing
    $ gh foo bar --flag value
`),
```

### JSON Output

Add `--json`, `--jq`, `--template` flags via `cmdutil.AddJSONFlags(cmd, &opts.Exporter, fieldNames)`. In the run function: `if opts.Exporter != nil { return opts.Exporter.Write(opts.IO, data) }`. See `pkg/cmd/pr/list/list.go`.

## Testing

### HTTP Mocking

Use `httpmock.Registry` with `defer reg.Verify(t)` to ensure all stubs are called:

```go
reg := &httpmock.Registry{}
defer reg.Verify(t)

reg.Register(
    httpmock.REST("GET", "repos/OWNER/REPO"),
    httpmock.JSONResponse(someData),
)
reg.Register(
    httpmock.GraphQL(`query PullRequestList\b`),
    httpmock.FileResponse("./fixtures/prList.json"),
)
client := &http.Client{Transport: reg}
```

Common: `REST(method, path)`, `GraphQL(pattern)`, `JSONResponse(body)`, `FileResponse(path)`. See `pkg/httpmock/` for all matchers/responders.

### IOStreams in Tests

```go
ios, stdin, stdout, stderr := iostreams.Test()
ios.SetStdoutTTY(true)  // simulate terminal
```

### Assertions

Use `testify`. Always use `require` (not `assert`) for error checks so the test halts immediately:

```go
require.NoError(t, err)
require.Error(t, err)
assert.Equal(t, "expected", actual)
```

### Generated Mocks

Interfaces use `moq`: `//go:generate moq -rm -out prompter_mock.go . Prompter`. Run `go generate ./...` after interface changes.

### Table-Driven Tests

Use table-driven tests for functions with multiple input/output scenarios. See `internal/agents/detect_test.go` or `pkg/cmd/issue/list/list_test.go` for examples:

```go
tests := []struct {
    name      string
    // inputs and expected outputs
}{
    {name: "descriptive case name", ...},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // arrange, act, assert
    })
}
```

## Code Style

- Add godoc comments to all exported functions, types, and constants
- Avoid unnecessary code comments — only comment when the *why* isn't obvious from the code
- Do not comment just to restate what the code does
- Never use em dashes (—) in code, comments, or documentation; use regular dashes (-) or rewrite the sentence instead

## Error Handling

Error types in `pkg/cmdutil/errors.go`:
- `FlagErrorf(...)` — flag validation (prints usage)
- `cmdutil.SilentError` — exit 1, no message
- `cmdutil.CancelError` — user cancelled
- `cmdutil.PendingError` — outcome pending
- `cmdutil.NoResultsError` — empty results

Use `cmdutil.MutuallyExclusive("message", cond1, cond2)` for mutually exclusive flags.

## Feature Detection

Commands using feature detection must include a `// TODO <cleanupIdentifier>` comment directly above the if-statement for linter compliance:

```go
// TODO someFeatureCleanup
if features.SomeCapability {
    // use new API
} else {
    // fallback for older GHES
}
```

## API Patterns

```go
client := api.NewClientFromHTTP(httpClient)
client.GraphQL(hostname, query, variables, &data)
client.REST(hostname, "GET", "repos/owner/repo", nil, &data)
```

For host resolution, use `cfg.Authentication().DefaultHost()` — not `ghinstance.Default()` which always returns `github.com`.

## Automic Vault Approval Gates

This fork intentionally carries small, command-local approval patches on top of
upstream `cli/cli`. When merging a new upstream release, verify that these gates
still sit immediately before the evaluated side effect and after target
resolution. Do not gate raw argv when the command later resolves a different
host, repository, run, workflow, or secret target.

Shared approval protocol:
- `internal/automicvault/approval.go`
- Fail closed when Automic Vault.app is unavailable or denies the request.
- Approval payloads should include host, resolved target, and action flags.
- Approval payloads must not include secret values, token values, request
  bodies, release notes, workflow inputs, or other sensitive content.

Required gate coverage:
- `gh auth token`: gate before reading or printing the token.
- `gh api`: gate REST `POST`, `PUT`, `PATCH`, and `DELETE`; gate GraphQL
  mutations and GraphQL requests read from `--input` because the operation
  cannot be inspected safely.
- `gh secret set` and `gh secret delete`: gate after resolving entity, app,
  host, repository, organization, environment, user, visibility, and secret
  names. Never include secret values.
- `gh repo delete`: gate after resolving the exact repository.
- `gh repo edit`: gate sensitive settings only, including visibility,
  default branch, fork/template/merge policy changes, and disabling security
  features.
- `gh pr merge`: gate `--admin`, `--delete-branch`, `--auto`, and
  `--disable-auto` paths after the pull request and base repository resolve.
- `gh release create` and `gh release delete`: gate before publishing,
  uploading assets, deleting releases, or deleting tags.
- `gh workflow run`, `gh workflow enable`, and `gh workflow disable`: gate
  after resolving the workflow and repository.
- `gh run rerun`, `gh run cancel`, and `gh run delete`: gate after resolving
  the run or job.
- `gh ssh-key add/delete` and `gh gpg-key add/delete`: gate after resolving
  the host and key metadata, before changing account authority.

Auth changes:
- Do not add an extra Automic Vault gate to normal browser/device auth flows.
  The GitHub browser hop is already a human approval boundary.
- Only gate `gh auth` changes that can complete without a browser/device hop,
  or that expose credentials directly.

Upstream merge checklist:
1. Search new or changed command packages for `REST(..., "POST"`,
   `REST(..., "PUT"`, `REST(..., "PATCH"`, `REST(..., "DELETE"`,
   `GraphQL` mutations, `http.NewRequest("POST"`, `http.NewRequest("PUT"`,
   `http.NewRequest("PATCH"`, and `http.NewRequest("DELETE"`.
2. Compare each write path against the approval criteria in the top-level
   repository README.
3. If a command already prompts, keep that prompt. Automic Vault approval is
   still required for agent and non-TTY execution at meaningful risk
   boundaries.
4. Keep every patch narrow. Prefer adding a command-local approval call over
   changing request construction or shared command behavior.
5. Add tests with an explicit approval stub for both approval and denial paths
   when changing a command gate.
