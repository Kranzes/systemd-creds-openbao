package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

func generate(t *testing.T, cfgTOML string) string {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgTOML))
	if err != nil {
		t.Fatal(err)
	}
	return Generate(cfg.Credentials)
}

// paths returns the paths the policy grants, in the order they appear.
func paths(hcl string) []string {
	var out []string
	for line := range strings.SplitSeq(hcl, "\n") {
		if rest, ok := strings.CutPrefix(line, `path "`); ok {
			p, _, _ := strings.Cut(rest, `"`)
			out = append(out, p)
		}
	}
	return out
}

func TestGenerate(t *testing.T) {
	got := generate(t, `
[[credentials]]
unit = "myapp.service"
credential = "db-password"
path = "myapp/database"

# Placeholder segments are only known per request.
[[credentials]]
unit = "*"
mount = "secret"
path = "systemd/{unit_name}/{credential}"

# The raw backend names the API path in full.
[[credentials]]
unit = "myapp.service"
credential = "dyn-db"
backend = "raw"
path = "database/creds/myapp"
format = "json"

# Two rules reading one path are granted once.
[[credentials]]
unit = "myapp.service"
credential = "db-user"
path = "myapp/database"
field = "username"
`)

	want := []string{
		"kv/data/myapp/database",
		"secret/data/systemd/+/+",
		"database/creds/myapp",
	}
	if p := paths(got); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if !strings.Contains(got, `capabilities = ["read"]`) {
		t.Errorf("policy grants no read capability:\n%s", got)
	}
}

func TestGeneratePinsPlaceholdersTheGlobsDetermine(t *testing.T) {
	// A rule whose globs carry no metacharacters matches one unit and one
	// credential ID, so it resolves to a single path and needs no wildcard.
	got := generate(t, `
[[credentials]]
unit = "nginx.service"
credential = "tls-key"
path = "certs/{unit_name}/{credential}"

# Pinning is what makes a mixed segment expressible, so this one stays exact.
[[credentials]]
unit = "web@prod.service"
credential = "config"
path = "systemd/site-{instance}/{credential}"

# The unit glob still matches many units, but the credential ID does not.
[[credentials]]
unit = "*.service"
credential = "db"
path = "systemd/{unit_name}/{credential}"

# A non-templated unit expands {instance} to nothing, which is not a path a
# rule can read, so the wildcard stays.
[[credentials]]
unit = "plain.service"
credential = "db"
path = "sites/{instance}/db"
`)

	want := []string{
		"kv/data/certs/nginx/tls-key",
		"kv/data/systemd/site-prod/config",
		"kv/data/systemd/+/db",
		"kv/data/sites/+/db",
	}
	if p := paths(got); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if strings.Contains(got, "# NOTE:") {
		t.Errorf("policy reports widening where a placeholder was pinned:\n%s", got)
	}
}

func TestGenerateWidensPartialSegments(t *testing.T) {
	// Policy wildcards cover a whole segment, so a segment mixing literal
	// text with a placeholder is granted more broadly than the rule reads.
	got := generate(t, `
[[credentials]]
unit = "web@*.service"
path = "systemd/site-{instance}/config"
`)

	want := []string{"kv/data/systemd/+/config"}
	if p := paths(got); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if !strings.Contains(got, "# NOTE:") {
		t.Errorf("policy does not flag the widened segment:\n%s", got)
	}
}
