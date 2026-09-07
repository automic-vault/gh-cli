#!/usr/bin/env python3
"""Exercise real macOS XPC request builders without contacting Secret Custody."""
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = root / "internal/keyring/keyring_darwin.go"
tests = root / "internal/keyring/keyring_darwin_test.go"

# Go does not support import C in _test.go. An overlay replaces only the
# transport boundary; set/get/delete and their XPC dictionaries remain real.
code = source.read_text()
start = code.index('\tservice := C.CString(approvalService)', code.index('func send('))
end = code.index('\nfunc replyError(', start)
code = code[:start].replace("os.Getwd()", "vaultTestGetwd()") + r'''
    cwdKey := C.CString("cwd")
    defer C.free(unsafe.Pointer(cwdKey))
    requestCWD := C.xpc_dictionary_get_string(message, cwdKey)
    if requestCWD == nil {
        return nil, errors.New("secret mutation is missing its working directory")
    }
    expected, wdErr := os.Getwd()
    if wdErr != nil { return nil, errors.New("transport reached without a working directory") }
    if C.GoString(requestCWD) != expected {
        return nil, errors.New("request working directory differs from process working directory")
    }
    reply := C.xpc_dictionary_create_empty()
    okKey := C.CString("ok")
    defer C.free(unsafe.Pointer(okKey))
    C.xpc_dictionary_set_bool(reply, okKey, true)
    return reply, nil
}
''' + code[end:]

extra_tests = r'''
var vaultTestGetwd = os.Getwd

func TestVaultRequestWorkingDirectory(t *testing.T) {
    t.Chdir(t.TempDir())
    for _, user := range []string{"", "mona"} {
        t.Run("save/"+user, func(t *testing.T) {
            require.NoError(t, set("gh:github.com", user, "test-token"))
        })
        t.Run("delete/"+user, func(t *testing.T) {
            require.NoError(t, deleteSecret("gh:github.com", user))
        })
        t.Run("read/"+user, func(t *testing.T) {
            _, err := get("gh:github.com", user)
            require.ErrorIs(t, err, ErrNotFound) // Transport validated cwd; reply has no token.
        })
    }
}

func TestVaultRequestMissingWorkingDirectory(t *testing.T) {
    original := vaultTestGetwd
    t.Cleanup(func() { vaultTestGetwd = original })
    vaultTestGetwd = func() (string, error) { return "", os.ErrNotExist }
    require.ErrorContains(t, set("gh:github.com", "mona", "test-token"), "failed to determine Automic Vault request working directory")
    require.ErrorContains(t, deleteSecret("gh:github.com", "mona"), "failed to determine Automic Vault request working directory")
    _, err := get("gh:github.com", "mona")
    require.ErrorContains(t, err, "failed to determine Automic Vault request working directory")
}
'''
with tempfile.TemporaryDirectory(prefix="gh-vault-test-") as directory:
    tmp = Path(directory)
    (tmp / "keyring.go").write_text(code)
    (tmp / "keyring_test.go").write_text(tests.read_text().replace('"testing"', '"testing"\n"os"') + extra_tests)
    (tmp / "overlay.json").write_text(json.dumps({"Replace": {
        str(source): str(tmp / "keyring.go"),
        str(tests): str(tmp / "keyring_test.go"),
    }}))
    subprocess.run([
        "go", "test", "-overlay", str(tmp / "overlay.json"),
        "./internal/keyring", "-run", "TestVaultRequest", "-count=1", "-v",
    ], cwd=root, check=True)
