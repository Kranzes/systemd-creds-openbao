// Package secrets maps systemd credential requests to OpenBao secrets using
// the configured rules.
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
)

// Reader reads secret data from OpenBao. It is implemented by *bao.Client.
type Reader interface {
	Read(ctx context.Context, ref config.SecretRef) (map[string]any, error)
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

	// One replacer serves every template of this request. See config.Replacer.
	expand := config.Replacer(config.PlaceholderValues(req.Unit, req.Credential))

	ref := config.SecretRef{Raw: rule.Backend == config.BackendRaw, Path: expand.Replace(rule.Path)}
	if err := config.CheckSegments("expanded path", ref.Path); err != nil {
		return nil, "", err
	}
	if !ref.Raw {
		ref.Mount = expand.Replace(rule.Mount)
		if err := config.CheckSegments("expanded mount", ref.Mount); err != nil {
			return nil, "", err
		}
	}
	location := ref.Location()

	data, err := r.reader.Read(ctx, ref)
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
	if value == nil {
		// JSON-encoding a null field would serve the literal text "null",
		// which looks like a real value. Refuse like a missing field instead.
		return nil, "", fmt.Errorf("secret %q field %q is null", location, field)
	}
	out, err := encodeField(value, rule.Encoding)
	if err != nil {
		return nil, "", fmt.Errorf("secret %q field %q: %w", location, field, err)
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
// Strings are served verbatim and any other type is JSON-encoded. With
// encoding = "base64" the string is decoded to raw bytes instead, since JSON
// has no byte string and credentials may be binary.
func encodeField(value any, encoding string) ([]byte, error) {
	switch v := value.(type) {
	case string:
		if encoding == config.EncodingBase64 {
			data, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("decoding base64 value: %w", err)
			}
			return data, nil
		}
		return []byte(v), nil
	default:
		if encoding == config.EncodingBase64 {
			return nil, fmt.Errorf("value is %T, base64 decoding takes a string", v)
		}
		out, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("encoding value: %w", err)
		}
		return out, nil
	}
}
