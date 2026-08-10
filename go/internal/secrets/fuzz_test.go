package secrets

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
	"github.com/kranzes/systemd-creds-openbao/go/internal/policy"
)

// FuzzResolve runs arbitrary rules through the real config validation and
// arbitrary requests through Resolve, and asserts two properties on every
// read that reaches the Reader: no segment is empty, "." or "..", and the
// policy -print-policy generates for the same rules grants the path being
// read. The rule goes through a TOML round trip because NewResolver's
// contract is a config that validation has accepted, and validation is part
// of what is under test.
func FuzzResolve(f *testing.F) {
	f.Add("*", "*", "", "", "systemd/{unit_name}", "", "", "", "myapp.service", "db-password")
	f.Add("foo@*.service", "*", "", "", "creds/{instance}", "", "", "", "foo@...service", "x")
	f.Add("myapp.service", "db-creds", "raw", "", "database/creds/myapp", "json", "", "", "myapp.service", "db-creds")
	f.Add("*", "*", "", "m-{prefix}", "{unit}/{credential}", "field", "db-password", "base64", "a@b.service", "count")

	f.Fuzz(func(t *testing.T, unitGlob, credGlob, backend, mount, path, format, field, encoding, unit, credential string) {
		// ParsePeer never produces an empty or slash-carrying unit or
		// credential ID. FuzzParsePeer holds it to that.
		if unit == "" || credential == "" || strings.ContainsRune(unit+credential, '/') {
			t.Skip()
		}

		// An empty value decodes like an absent key, so one rule shape
		// covers every combination of set and unset keys.
		var buf bytes.Buffer
		err := toml.NewEncoder(&buf).Encode(map[string]any{"credentials": []map[string]string{{
			"unit":       unitGlob,
			"credential": credGlob,
			"backend":    backend,
			"mount":      mount,
			"path":       path,
			"format":     format,
			"field":      field,
			"encoding":   encoding,
		}}})
		if err != nil {
			t.Skip()
		}
		cfg, err := config.Parse(buf.Bytes())
		if err != nil {
			t.Skip()
		}

		r := NewResolver(cfg.Credentials, &checkingReader{t: t, policy: policyPaths(cfg.Credentials)})
		r.Resolve(context.Background(), credserver.Request{Unit: unit, Credential: credential})
	})
}

// checkingReader stands in for OpenBao and asserts FuzzResolve's properties
// on every read instead of serving anything real. The data it returns covers
// each encodeField branch, so the code past the read runs too.
type checkingReader struct {
	t      *testing.T
	policy []string
}

var fuzzSecretData = map[string]any{
	"password":    "hunter2",
	"db-password": "aHVudGVyMg==",
	"count":       float64(3),
}

func (c *checkingReader) Read(_ context.Context, ref config.SecretRef) (map[string]any, error) {
	c.cleanSegments(ref.Path)
	if ref.Raw {
		c.granted(ref.Path)
		return fuzzSecretData, nil
	}
	c.cleanSegments(ref.Mount)
	c.granted(ref.Mount + "/data/" + ref.Path)
	return fuzzSecretData, nil
}

func (c *checkingReader) cleanSegments(p string) {
	c.t.Helper()
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			c.t.Errorf("a read reached OpenBao with an empty, %q or %q segment: %q", ".", "..", p)
		}
	}
}

func (c *checkingReader) granted(read string) {
	c.t.Helper()
	if !slices.ContainsFunc(c.policy, func(p string) bool { return covers(p, read) }) {
		c.t.Errorf("read %q is not granted by the generated policy paths %q", read, c.policy)
	}
}

// covers applies OpenBao's matching for the one wildcard the generator
// emits: "+" matches any single segment.
func covers(policyPath, read string) bool {
	want := strings.Split(read, "/")
	segments := strings.Split(policyPath, "/")
	if len(segments) != len(want) {
		return false
	}
	for i, seg := range segments {
		if seg != "+" && seg != want[i] {
			return false
		}
	}
	return true
}

// policyPaths is what the generated policy grants.
func policyPaths(rules []config.Credential) []string {
	var paths []string
	for _, g := range policy.Grants(rules) {
		paths = append(paths, g.Path)
	}
	return paths
}
