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
	kv  map[string]map[string]any // "mount/path" -> data
	raw map[string]map[string]any // "path" -> data
}

func (f *fakeReader) Read(_ context.Context, ref config.SecretRef) (map[string]any, error) {
	from := f.kv
	if ref.Raw {
		from = f.raw
	}
	data, ok := from[ref.Location()]
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

func TestResolveNullField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"password": nil},
	}})

	// A present-but-null field must refuse the request. JSON-encoded it would
	// serve the four bytes "null", which a consumer reads as a real value.
	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "password"})
	if err == nil || !strings.Contains(err.Error(), "null") {
		t.Errorf("err = %v, want null-field error", err)
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

func TestResolveBase64Encoding(t *testing.T) {
	reader := &fakeReader{kv: map[string]map[string]any{
		"kv/p": {
			"blob":   base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff}),
			"broken": "!!!not-base64!!!",
			"count":  3,
		},
	}}
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
encoding = "base64"
`, reader)

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

	// A non-string field holds no base64 text to decode.
	if _, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "count"}); err == nil {
		t.Error("Resolve succeeded for a non-string field, want error")
	}

	// Without the option the same value is served as the text it is.
	r = newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, reader)
	got, _, err = r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "blob"})
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff}); string(got) != want {
		t.Errorf("got %q, want %q", got, want)
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

	// The instance name comes from whoever defines the unit, so ".." must not
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

func TestPlan(t *testing.T) {
	// The nil reader proves a plan never contacts OpenBao.
	r := newResolver(t, `
[[credentials]]
unit = "other.service"
path = "other"

[[credentials]]
unit = "worker@*.service"
path = "app/{prefix}/{instance}"
`, nil)

	plan, err := r.Plan(credserver.Request{Unit: "worker@a.service", Credential: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RuleIndex != 2 {
		t.Errorf("RuleIndex = %d, want 2", plan.RuleIndex)
	}
	if got, want := plan.Ref.Location(), "kv/app/worker/a"; got != want {
		t.Errorf("location = %q, want %q", got, want)
	}
	if got, want := plan.Field, "db-password"; got != want {
		t.Errorf("field = %q, want %q", got, want)
	}
}

func TestPlanJSONFormatHasNoField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "myapp.service"
backend = "raw"
path = "database/creds/myapp"
format = "json"
`, nil)

	plan, err := r.Plan(credserver.Request{Unit: "myapp.service", Credential: "db-creds"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Ref.Location(), "database/creds/myapp"; got != want {
		t.Errorf("location = %q, want %q", got, want)
	}
	if plan.Field != "" {
		t.Errorf("field = %q, want empty", plan.Field)
	}
}

func TestPlanNoMatchIsRefused(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "myapp.service"
path = "myapp/db"
`, nil)

	_, err := r.Plan(credserver.Request{Unit: "intruder.service", Credential: "db-password"})
	if err == nil || !strings.Contains(err.Error(), "no credential rule matches") {
		t.Errorf("err = %v, want no-match refusal", err)
	}
}
