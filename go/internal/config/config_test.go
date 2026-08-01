package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
[[credentials]]
unit = "*"
path = "systemd/{unit_name}"
`))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := cfg.OpenBao.Auth.Method, AuthToken; got != want {
		t.Errorf("auth method = %q, want %q", got, want)
	}
	if got, want := cfg.Server.ConnectionTimeout, 15*time.Second; got != want {
		t.Errorf("connection timeout = %v, want %v", got, want)
	}

	r := cfg.Credentials[0]
	if r.Credential != "*" {
		t.Errorf("credential glob = %q, want *", r.Credential)
	}
	if r.Backend != BackendKV || r.Mount != "kv" {
		t.Errorf("backend defaults = %q/%q, want kv/kv", r.Backend, r.Mount)
	}
	if r.Format != FormatField || r.Field != "{credential}" {
		t.Errorf("format defaults = %q/%q, want field/{credential}", r.Format, r.Field)
	}
}

func TestParseFull(t *testing.T) {
	cfg, err := Parse([]byte(`
[openbao]
serve_stale_for = "1h"

[openbao.auth]
method = "approle"
role_id = "my-role"
secret_id_file = "/etc/openbao/secret-id"

[[credentials]]
unit = "myapp.service"
credential = "db-*"
mount = "kv"
path = "myapp/database"

[[credentials]]
unit = "*"
credential = "dyn-db"
backend = "raw"
path = "database/creds/myapp"
format = "json"
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.OpenBao.ServeStaleFor != time.Hour {
		t.Errorf("serve_stale_for = %v, want 1h", cfg.OpenBao.ServeStaleFor)
	}
	if r := cfg.Credentials[0]; r.Mount != "kv" {
		t.Errorf("rule 0 mount = %q, want kv", r.Mount)
	}
	if r := cfg.Credentials[1]; r.Backend != BackendRaw || r.Format != FormatJSON || r.Field != "" {
		t.Errorf("rule 1 = %+v, want raw/json without field", r)
	}
}

func TestParseCert(t *testing.T) {
	cfg, err := Parse([]byte(`
[openbao.auth]
method = "cert"
cert_role = "web-servers"

[[credentials]]
unit = "*"
path = "p"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OpenBao.Auth.Mount; got != "cert" {
		t.Errorf("cert mount default = %q, want cert", got)
	}
}

func TestParseJWT(t *testing.T) {
	cfg, err := Parse([]byte(`
[openbao.auth]
method = "jwt"
jwt_file = "/run/secrets/jwt"
jwt_role = "systemd-creds"

[[credentials]]
unit = "*"
path = "p"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OpenBao.Auth.Mount; got != "jwt" {
		t.Errorf("jwt mount default = %q, want jwt", got)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want string // substring of the error
	}{
		{
			name: "unknown key",
			toml: "[openbao]\naddres = \"typo\"",
			want: "unknown configuration keys",
		},
		{
			name: "unknown auth method",
			toml: "[openbao.auth]\nmethod = \"userpass\"",
			want: "unknown method",
		},
		{
			name: "approle without role_id",
			toml: "[openbao.auth]\nmethod = \"approle\"\nsecret_id_file = \"/f\"",
			want: "role_id",
		},
		{
			name: "approle with both role_id and role_id_file",
			toml: "[openbao.auth]\nmethod = \"approle\"\nrole_id = \"r\"\nrole_id_file = \"/f\"\nsecret_id_file = \"/f\"",
			want: "role_id",
		},
		{
			name: "approle without secret_id_file",
			toml: "[openbao.auth]\nmethod = \"approle\"\nrole_id = \"r\"",
			want: "secret_id_file is required",
		},
		{
			// The secret ID is confidential: it has no inline key.
			name: "approle with inline secret_id",
			toml: "[openbao.auth]\nmethod = \"approle\"\nrole_id = \"r\"\nsecret_id = \"s\"",
			want: "openbao.auth.secret_id",
		},
		{
			name: "token method with approle options",
			toml: "[openbao.auth]\nrole_id = \"r\"",
			want: "approle options set",
		},
		{
			name: "token method with cert options",
			toml: "[openbao.auth]\ncert_role = \"web-servers\"",
			want: "cert options set",
		},
		{
			name: "cert method with token options",
			toml: "[openbao.auth]\nmethod = \"cert\"\ntoken_file = \"/f\"",
			want: "token options set",
		},
		{
			name: "cert method with approle options",
			toml: "[openbao.auth]\nmethod = \"cert\"\nrole_id = \"r\"",
			want: "approle options set",
		},
		{
			name: "token method with a mount",
			toml: "[openbao.auth]\nmount = \"token\"",
			want: "mount is set",
		},
		{
			name: "jwt without jwt_file",
			toml: "[openbao.auth]\nmethod = \"jwt\"\njwt_role = \"r\"",
			want: "jwt_file is required",
		},
		{
			// The JWT is a bearer credential: it has no inline key.
			name: "jwt with inline jwt",
			toml: "[openbao.auth]\nmethod = \"jwt\"\njwt = \"eyJ...\"\njwt_role = \"r\"",
			want: "openbao.auth.jwt",
		},
		{
			name: "token method with jwt options",
			toml: "[openbao.auth]\njwt_role = \"r\"",
			want: "jwt options set",
		},
		{
			name: "jwt method with approle options",
			toml: "[openbao.auth]\nmethod = \"jwt\"\njwt_file = \"/f\"\nrole_id = \"r\"",
			want: "approle options set",
		},
		{
			name: "rule without unit",
			toml: "[[credentials]]\npath = \"p\"",
			want: "unit is required",
		},
		{
			name: "rule without path",
			toml: "[[credentials]]\nunit = \"u.service\"\ncredential = \"x\"",
			want: "path is required",
		},
		{
			name: "raw backend with mount",
			toml: "[[credentials]]\nunit = \"u.service\"\nbackend = \"raw\"\npath = \"p\"\nmount = \"m\"",
			want: "mount must not be set",
		},
		{
			name: "json format with field",
			toml: "[[credentials]]\nunit = \"u.service\"\npath = \"p\"\nformat = \"json\"\nfield = \"f\"",
			want: "field must not be set",
		},
		{
			name: "bad unit glob",
			toml: "[[credentials]]\nunit = \"[oops\"\npath = \"p\"",
			want: "invalid glob",
		},
		{
			name: "bad duration",
			toml: "[server]\nconnection_timeout = \"fast\"",
			want: "duration",
		},
		{
			name: "negative connection timeout",
			toml: "[server]\nconnection_timeout = \"-15s\"",
			want: "connection_timeout must not be negative",
		},
		{
			// A bare integer is nanoseconds, so "15" is not "15s".
			name: "bare integer connection timeout",
			toml: "[server]\nconnection_timeout = 15",
			want: "too short to be meant",
		},
		{
			name: "negative serve_stale_for",
			toml: "[openbao]\nserve_stale_for = \"-1h\"",
			want: "serve_stale_for must not be negative",
		},
		{
			name: "bare integer serve_stale_for",
			toml: "[openbao]\nserve_stale_for = 3600",
			want: "too short to be meant",
		},
		{
			// The resolver refuses these at request time, so such a rule
			// could never serve anything.
			name: "path with an empty segment",
			toml: "[[credentials]]\nunit = \"u.service\"\npath = \"systemd//db\"",
			want: "empty",
		},
		{
			name: "path with a parent segment",
			toml: "[[credentials]]\nunit = \"u.service\"\npath = \"systemd/../db\"",
			want: "segment",
		},
		{
			name: "mount with a trailing slash",
			toml: "[[credentials]]\nunit = \"u.service\"\nmount = \"kv/\"\npath = \"db\"",
			want: "segment",
		},
		{
			// Unit and credential are globs, but the path is not: a wildcard
			// there is literal to the resolver and a wildcard to the policy,
			// so the rule would grant a subtree it can never read from.
			name: "path with a trailing wildcard",
			toml: "[[credentials]]\nunit = \"u.service\"\npath = \"apps/*\"",
			want: "wildcard",
		},
		{
			name: "path that is only a wildcard",
			toml: "[[credentials]]\nunit = \"u.service\"\nbackend = \"raw\"\npath = \"*\"",
			want: "wildcard",
		},
		{
			name: "path with a wildcard segment",
			toml: "[[credentials]]\nunit = \"u.service\"\npath = \"apps/+/db\"",
			want: "wildcard",
		},
		{
			name: "mount with a wildcard",
			toml: "[[credentials]]\nunit = \"u.service\"\nmount = \"kv*\"\npath = \"db\"",
			want: "wildcard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.toml))
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestParseAllowsWildcardCharactersInsideASegment(t *testing.T) {
	// "+" is a wildcard only as a whole segment and "*" only at the end, so a
	// path like "c++" is literal to OpenBao and has to stay valid.
	const path = "apps/c++/db"
	cfg, err := Parse([]byte("[[credentials]]\nunit = \"u.service\"\npath = \"" + path + "\""))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Credentials[0].Path; got != path {
		t.Errorf("path = %q, want %q", got, path)
	}
}

func TestPinnedValues(t *testing.T) {
	// A glob with no metacharacters matches one string, so everything it feeds
	// is known ahead of any request.
	pinned := PinnedValues("web@prod.service", "tls-key")
	want := map[string]string{
		"{unit}":       "web@prod.service",
		"{unit_name}":  "web@prod",
		"{prefix}":     "web",
		"{instance}":   "prod",
		"{credential}": "tls-key",
	}
	for p, w := range want {
		if got := pinned[p]; got != w {
			t.Errorf("PinnedValues[%s] = %q, want %q", p, got, w)
		}
	}

	// A glob that can match more than one unit pins none of the values it
	// feeds, while the credential ID is independent of it.
	pinned = PinnedValues("web@*.service", "tls-key")
	for _, p := range []string{"{unit}", "{unit_name}", "{prefix}", "{instance}"} {
		if v, ok := pinned[p]; ok {
			t.Errorf("PinnedValues[%s] = %q, want it left free", p, v)
		}
	}
	if got := pinned["{credential}"]; got != "tls-key" {
		t.Errorf("PinnedValues[{credential}] = %q, want %q", got, "tls-key")
	}

	// A non-templated unit has no instance, and an empty segment is not a path
	// any rule can read, so there is nothing to pin it to.
	if v, ok := PinnedValues("plain.service", "*")["{instance}"]; ok {
		t.Errorf("PinnedValues[{instance}] = %q, want it left free", v)
	}
}
