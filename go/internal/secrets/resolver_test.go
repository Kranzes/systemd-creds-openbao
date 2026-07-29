package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
)

type fakeReader struct {
	kv  map[string]map[string]any // "mount/path" → data
	raw map[string]map[string]any // "path" → data
}

func (f *fakeReader) ReadKV(_ context.Context, mount, path string) (map[string]any, error) {
	data, ok := f.kv[mount+"/"+path]
	if !ok {
		return nil, errNotFound
	}
	return data, nil
}

func (f *fakeReader) ReadRaw(_ context.Context, path string) (map[string]any, error) {
	data, ok := f.raw[path]
	if !ok {
		return nil, errNotFound
	}
	return data, nil
}

var errNotFound = errors.New("secret not found")

func newResolver(t *testing.T, toml string, reader Reader) *Resolver {
	t.Helper()
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	return NewResolver(cfg.Credentials, reader)
}

func TestResolveField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "myapp.service"
credential = "db-password"
path = "myapp/db"
field = "password"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/myapp/db": {"password": "hunter2"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestResolveTemplates(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "systemd/{unit_name}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/systemd/myapp": {"db-password": "hunter2"},
	}})

	got, gotPath, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
	if gotPath != "kv/systemd/myapp" {
		t.Errorf("got path %q, want %q", gotPath, "kv/systemd/myapp")
	}
}

func TestResolveFirstMatchWins(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "special.service"
path = "special"
field = "value"

[[credentials]]
unit = "*"
path = "fallback"
field = "value"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/special":  {"value": "from-special"},
		"kv/fallback": {"value": "from-fallback"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "special.service", Credential: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-special" {
		t.Errorf("got %q, want %q", got, "from-special")
	}

	got, _, err = r.Resolve(context.Background(), credserver.Request{Unit: "other.service", Credential: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-fallback" {
		t.Errorf("got %q, want %q", got, "from-fallback")
	}
}

func TestResolveNoMatchIsRefused(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "onlythis.service"
path = "p"
`, &fakeReader{})

	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "other.service", Credential: "x"})
	if err == nil || !strings.Contains(err.Error(), "no credential rule matches") {
		t.Errorf("err = %v, want no-rule-matches error", err)
	}
}

func TestResolveMissingField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"other": "x"},
	}})

	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "missing"})
	if err == nil || !strings.Contains(err.Error(), `no field "missing"`) {
		t.Errorf("err = %v, want missing-field error", err)
	}
}

func TestResolveJSONFormat(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
backend = "raw"
path = "database/creds/myapp"
format = "json"
`, &fakeReader{raw: map[string]map[string]any{
		"database/creds/myapp": {"username": "u", "password": "p"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if decoded["username"] != "u" || decoded["password"] != "p" {
		t.Errorf("decoded = %v", decoded)
	}
}

func TestResolveNonStringField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"port": json.Number("5432"), "flags": map[string]any{"a": true}},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "port"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "5432" {
		t.Errorf("number field = %q, want 5432", got)
	}

	got, _, err = r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "flags"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":true}` {
		t.Errorf("object field = %q, want JSON object", got)
	}
}

func TestResolveBase64Field(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {
			"blob":   "base64:" + base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff}),
			"broken": "base64:!!!not-base64!!!",
		},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "blob"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x00, 0x01, 0xff}; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Invalid base64 refuses the credential instead of serving mangled bytes.
	if _, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "broken"}); err == nil {
		t.Error("Resolve succeeded for invalid base64, want error")
	}
}

func TestResolveRejectsUncleanExpandedPath(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "apps/{instance}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/apps/..": {"c": "x"},
		"kv/apps/":   {"c": "x"},
	}})

	// The instance name comes from whoever defines the unit: ".." must not
	// escape the rule's path prefix through URL normalization, and an empty
	// instance must not serve a path the rule never granted.
	for _, unit := range []string{"foo@...service", "plain.service"} {
		_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: unit, Credential: "c"})
		if err == nil || !strings.Contains(err.Error(), "segment") {
			t.Errorf("unit %s: err = %v, want unclean-path error", unit, err)
		}
	}

	r = newResolver(t, `
[[credentials]]
unit = "*"
mount = "{instance}"
path = "p"
`, &fakeReader{})
	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "foo@...service", Credential: "c"})
	if err == nil || !strings.Contains(err.Error(), "segment") {
		t.Errorf("mount: err = %v, want unclean-path error", err)
	}
}

func TestExpand(t *testing.T) {
	req := credserver.Request{Unit: "foo@bar.service", Credential: "cred"}
	tests := []struct{ tmpl, want string }{
		{"{unit}", "foo@bar.service"},
		{"{unit_name}", "foo@bar"},
		{"{prefix}", "foo"},
		{"{instance}", "bar"},
		{"{credential}", "cred"},
		{"systemd/{prefix}/{credential}", "systemd/foo/cred"},
	}
	for _, tt := range tests {
		if got := expand(tt.tmpl, req); got != tt.want {
			t.Errorf("expand(%q) = %q, want %q", tt.tmpl, got, tt.want)
		}
	}

	plain := credserver.Request{Unit: "myapp.service", Credential: "c"}
	if got := expand("{instance}", plain); got != "" {
		t.Errorf("instance of non-templated unit = %q, want empty", got)
	}
	if got := expand("{prefix}", plain); got != "myapp" {
		t.Errorf("prefix of non-templated unit = %q, want myapp", got)
	}
}

// The policy generator wildcards a segment by matching config.Placeholders, so
// a placeholder expand substitutes but the list omits would be granted as a
// literal segment. expand reads the same list, leaving only this direction to
// check.
func TestExpandSubstitutesEveryDocumentedPlaceholder(t *testing.T) {
	req := credserver.Request{Unit: "foo@bar.service", Credential: "cred"}
	for _, p := range config.Placeholders {
		if got := expand(p, req); got == p {
			t.Errorf("expand(%q) = %q, want a substituted value", p, got)
		}
	}
	if got := expand("{unknown}", req); got != "{unknown}" {
		t.Errorf("expand(%q) = %q, want it left alone", "{unknown}", got)
	}
}
