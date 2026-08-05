package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

func rules(t *testing.T, cfgTOML string) []config.Credential {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgTOML))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Credentials
}

// paths returns the paths the grants allow, in the order they appear.
func paths(grants []Grant) []string {
	var out []string
	for _, g := range grants {
		out = append(out, g.Path)
	}
	return out
}

// widened returns the paths granted more broadly than the rules read.
func widened(grants []Grant) []string {
	var out []string
	for _, g := range grants {
		if g.Widened {
			out = append(out, g.Path)
		}
	}
	return out
}

func TestGenerate(t *testing.T) {
	r := rules(t, `
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
	if p := paths(Grants(r)); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if got := Generate(r); !strings.Contains(got, `capabilities = ["read"]`) {
		t.Errorf("policy grants no read capability:\n%s", got)
	}
}

func TestGeneratePinsPlaceholdersTheGlobsDetermine(t *testing.T) {
	// A rule whose globs carry no metacharacters matches one unit and one
	// credential ID, so it resolves to a single path and needs no wildcard.
	r := rules(t, `
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

# The instance varies, but the template glob's literal text before the "@"
# still fixes the prefix.
[[credentials]]
unit = "worker@*.service"
credential = "queue"
path = "app/{prefix}/{instance}"
`)

	want := []string{
		"kv/data/certs/nginx/tls-key",
		"kv/data/systemd/site-prod/config",
		"kv/data/systemd/+/db",
		"kv/data/app/worker/+",
	}
	if p := paths(Grants(r)); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if w := widened(Grants(r)); len(w) != 0 {
		t.Errorf("grants widened where a placeholder was pinned: %q", w)
	}
}

func TestGenerateWidensPartialSegments(t *testing.T) {
	// Policy wildcards cover a whole segment, so a segment mixing literal
	// text with a placeholder is granted more broadly than the rule reads.
	r := rules(t, `
[[credentials]]
unit = "web@*.service"
path = "systemd/site-{instance}/config"
`)

	want := []string{"kv/data/systemd/+/config"}
	if p := paths(Grants(r)); !slices.Equal(p, want) {
		t.Errorf("granted paths = %q, want %q", p, want)
	}
	if w := widened(Grants(r)); !slices.Equal(w, want) {
		t.Errorf("widened = %q, want %q", w, want)
	}
	if got := Generate(r); !strings.Contains(got, "# NOTE:") {
		t.Errorf("policy does not flag the widened segment:\n%s", got)
	}
}
