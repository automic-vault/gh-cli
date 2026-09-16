package context

import (
	"net/url"
	"testing"

	"github.com/cli/cli/v2/git"
	"github.com/cli/cli/v2/internal/ghrepo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Remotes_FindByName(t *testing.T) {
	list := Remotes{
		&Remote{Remote: &git.Remote{Name: "mona"}, Repo: ghrepo.New("monalisa", "myfork")},
		&Remote{Remote: &git.Remote{Name: "origin"}, Repo: ghrepo.New("monalisa", "octo-cat")},
		&Remote{Remote: &git.Remote{Name: "upstream"}, Repo: ghrepo.New("hubot", "tools")},
	}

	r, err := list.FindByName("upstream", "origin")
	assert.NoError(t, err)
	assert.Equal(t, "upstream", r.Name)

	r, err = list.FindByName("nonexistent", "*")
	assert.NoError(t, err)
	assert.Equal(t, "mona", r.Name)

	_, err = list.FindByName("nonexistent")
	assert.Error(t, err, "no GitHub remotes found")
}

func Test_Remotes_FindByRepo(t *testing.T) {
	list := Remotes{
		&Remote{Remote: &git.Remote{Name: "remote-0"}, Repo: ghrepo.New("owner", "repo")},
		&Remote{Remote: &git.Remote{Name: "remote-1"}, Repo: ghrepo.New("another-owner", "another-repo")},
	}

	tests := []struct {
		name        string
		owner       string
		repo        string
		wantsRemote *Remote
		wantsError  string
	}{
		{
			name:        "exact match (owner/repo)",
			owner:       "owner",
			repo:        "repo",
			wantsRemote: list[0],
		},
		{
			name:        "exact match (another-owner/another-repo)",
			owner:       "another-owner",
			repo:        "another-repo",
			wantsRemote: list[1],
		},
		{
			name:        "case-insensitive match",
			owner:       "OWNER",
			repo:        "REPO",
			wantsRemote: list[0],
		},
		{
			name:       "non-match (owner)",
			owner:      "unknown-owner",
			repo:       "repo",
			wantsError: "no matching remote found; looking for unknown-owner/repo",
		},
		{
			name:       "non-match (repo)",
			owner:      "owner",
			repo:       "unknown-repo",
			wantsError: "no matching remote found; looking for owner/unknown-repo",
		},
		{
			name:       "non-match (owner, repo)",
			owner:      "unknown-owner",
			repo:       "unknown-repo",
			wantsError: "no matching remote found; looking for unknown-owner/unknown-repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := list.FindByRepo(tt.owner, tt.repo)
			if tt.wantsError != "" {
				assert.Error(t, err, tt.wantsError)
				assert.Nil(t, r)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, r, tt.wantsRemote)
			}
		})
	}
}

type identityTranslator struct{}

func (it identityTranslator) Translate(u *url.URL) *url.URL {
	return u
}

func Test_translateRemotes(t *testing.T) {
	publicURL, _ := url.Parse("https://github.com/monalisa/hello")
	originURL, _ := url.Parse("http://example.com/repo")

	gitRemotes := git.RemoteSet{
		&git.Remote{
			Name:     "origin",
			FetchURL: originURL,
		},
		&git.Remote{
			Name:     "public",
			FetchURL: publicURL,
		},
	}

	result := TranslateRemotes(gitRemotes, identityTranslator{})

	if len(result) != 1 {
		t.Errorf("got %d results", len(result))
	}
	if result[0].Name != "public" {
		t.Errorf("got %q", result[0].Name)
	}
	if result[0].RepoName() != "hello" {
		t.Errorf("got %q", result[0].RepoName())
	}
}

func Test_FilterByHosts(t *testing.T) {
	r1 := &Remote{Remote: &git.Remote{Name: "mona"}, Repo: ghrepo.NewWithHost("monalisa", "myfork", "test.com")}
	r2 := &Remote{Remote: &git.Remote{Name: "origin"}, Repo: ghrepo.NewWithHost("monalisa", "octo-cat", "example.com")}
	r3 := &Remote{Remote: &git.Remote{Name: "upstream"}, Repo: ghrepo.New("hubot", "tools")}
	list := Remotes{r1, r2, r3}
	f := list.FilterByHosts([]string{"example.com", "test.com"})
	assert.Equal(t, 2, len(f))
	assert.Equal(t, r1, f[0])
	assert.Equal(t, r2, f[1])
}

func TestTranslateRemotesVault(t *testing.T) {
	for _, tt := range []struct {
		raw   string
		valid bool
	}{
		{"av::https://github.com/monalisa/octo-cat.git", true},
		{"https://github.com/monalisa/octo-cat.git", true},
		{"git@github.com:monalisa/octo-cat.git", true},
		{"av::http://github.com/monalisa/octo-cat.git", false},
		{"av::ssh://git@github.com/monalisa/octo-cat.git", false},
		{"av::https://example.com/monalisa/octo-cat.git", false},
		{"av::https://github.com.evil.test/monalisa/octo-cat.git", false},
		{"av::https://github.com@evil.test/monalisa/octo-cat.git", false},
		{"av::https://user@github.com/monalisa/octo-cat.git", false},
		{"av::https://github.com:443/monalisa/octo-cat.git", false},
		{"av::https://github.com/monalisa/octo-cat", false},
		{"av::https://github.com/monalisa/octo-cat.git/extra", false},
		{"av::https://github.com/monalisa/octo-cat.git?query=1", false},
		{"av::https://github.com/monalisa/octo-cat.git#fragment", false},
		{"av::https://github.com/monalisa/octo%2dcat.git", false},
		{"av::https://github.com//octo-cat.git", false},
		{"av::https://github.com/../octo-cat.git", false},
		{"av::https://github.com/monalisa/...git", false},
		{"av::av::https://github.com/monalisa/octo-cat.git", false},
		{"av:https://github.com/monalisa/octo-cat.git", false},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := git.ParseURL(tt.raw)
			require.NoError(t, err)
			original := u.String()
			for _, remote := range []*git.Remote{
				{Name: "origin", FetchURL: u},
				{Name: "origin", PushURL: u},
			} {
				result := TranslateRemotes(git.RemoteSet{remote}, identityTranslator{})
				if !tt.valid {
					require.Empty(t, result)
					continue
				}
				require.Len(t, result, 1)
				assert.Equal(t, "github.com", result[0].RepoHost())
				assert.Equal(t, "monalisa/octo-cat", ghrepo.FullName(result[0]))
				assert.Same(t, remote, result[0].Remote)
				assert.Equal(t, original, u.String())
				if u.Scheme == "av" {
					assert.Equal(t, tt.raw, u.String())
				}
			}
		})
	}
}
