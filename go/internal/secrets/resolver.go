// Package secrets maps systemd credential requests to OpenBao secrets using
// the configured rules.
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
)

// Reader reads secret data from OpenBao. It is implemented by *bao.Client.
type Reader interface {
	ReadKV(ctx context.Context, mount, secretPath string) (map[string]any, error)
	ReadRaw(ctx context.Context, apiPath string) (map[string]any, error)
}

// Resolver resolves credential requests against a rule list, first match wins.
// It implements credserver.Resolver.
type Resolver struct {
	rules  []config.Credential
	reader Reader
}

// NewResolver returns a Resolver for rules that config has already validated.
func NewResolver(rules []config.Credential, reader Reader) *Resolver {
	return &Resolver{rules: rules, reader: reader}
}

// Resolve implements credserver.Resolver.
func (r *Resolver) Resolve(ctx context.Context, req credserver.Request) ([]byte, string, error) {
	rule := r.match(req)
	if rule == nil {
		return nil, "", fmt.Errorf("no credential rule matches unit %q credential %q", req.Unit, req.Credential)
	}

	// One replacer serves every template of this request; see config.Replacer.
	expand := config.Replacer(config.PlaceholderValues(req.Unit, req.Credential))

	secretPath := expand.Replace(rule.Path)
	if err := config.CheckSegments("expanded path", secretPath); err != nil {
		return nil, "", err
	}
	var (
		data map[string]any
		err  error
	)
	location := secretPath
	switch rule.Backend {
	case config.BackendRaw:
		data, err = r.reader.ReadRaw(ctx, secretPath)
	default:
		mount := expand.Replace(rule.Mount)
		if err := config.CheckSegments("expanded mount", mount); err != nil {
			return nil, "", err
		}
		location = mount + "/" + secretPath
		data, err = r.reader.ReadKV(ctx, mount, secretPath)
	}
	if err != nil {
		return nil, "", fmt.Errorf("reading %q: %w", location, err)
	}

	if rule.Format == config.FormatJSON {
		out, err := json.Marshal(data)
		if err != nil {
			return nil, "", fmt.Errorf("encoding secret %q as JSON: %w", location, err)
		}
		return out, location, nil
	}

	field := expand.Replace(rule.Field)
	value, ok := data[field]
	if !ok {
		return nil, "", fmt.Errorf("secret %q has no field %q", location, field)
	}
	out, err := encodeField(value)
	if err != nil {
		return nil, "", err
	}
	return out, location, nil
}

func (r *Resolver) match(req credserver.Request) *config.Credential {
	for i := range r.rules {
		rule := &r.rules[i]
		// Patterns are validated at config load, so Match cannot fail here.
		unitOK, _ := path.Match(rule.Unit, req.Unit)
		credOK, _ := path.Match(rule.Credential, req.Credential)
		if unitOK && credOK {
			return rule
		}
	}
	return nil
}

// encodeField turns one field of the secret data into the credential payload.
// Strings are served verbatim, except that a "base64:" prefix decodes to raw
// bytes, since JSON has no byte string and credentials may be binary. Any
// other type is JSON-encoded.
func encodeField(value any) ([]byte, error) {
	switch v := value.(type) {
	case string:
		if enc, ok := strings.CutPrefix(v, "base64:"); ok {
			data, err := base64.StdEncoding.DecodeString(enc)
			if err != nil {
				return nil, fmt.Errorf("decoding base64 secret value: %w", err)
			}
			return data, nil
		}
		return []byte(v), nil
	default:
		out, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("encoding field value: %w", err)
		}
		return out, nil
	}
}
