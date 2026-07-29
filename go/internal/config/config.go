// Package config loads the TOML configuration file, applies defaults, and
// validates the result.
package config

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Authentication methods for OpenBao.
const (
	AuthToken   = "token"
	AuthAppRole = "approle"
	AuthCert    = "cert"
	AuthJWT     = "jwt"
)

// Secret backends a credential rule can read from.
const (
	BackendKV  = "kv"  // KV v2; v1 is only reachable through raw
	BackendRaw = "raw" // verbatim read of an arbitrary API path
)

// Output formats for a credential rule.
const (
	FormatField = "field" // a single field of the secret, verbatim
	FormatJSON  = "json"  // the whole secret data, JSON-encoded
)

// Config is the root of the configuration file.
type Config struct {
	OpenBao     OpenBao      `toml:"openbao"`
	Server      Server       `toml:"server"`
	Credentials []Credential `toml:"credentials"`
}

// OpenBao holds how the daemon authenticates to the OpenBao server. The
// connection itself (address, TLS, namespace, timeout) has no config keys and
// comes only from the BAO_*/VAULT_* environment variables.
type OpenBao struct {
	Auth Auth `toml:"auth"`
}

// Auth configures how the daemon authenticates to OpenBao.
//
// The *_file paths are environment-expanded when read
// (${CREDENTIALS_DIRECTORY}/...), and an unset variable is an error.
type Auth struct {
	// Method is "token" (default), "approle", "cert", or "jwt".
	Method string `toml:"method"`

	// Required for token auth. Unset, the client library's
	// BAO_TOKEN/VAULT_TOKEN is used instead, which is how the tests drive
	// token auth; a deployment passes the token as a file, since systemd
	// exposes a unit's environment to any local user.
	TokenFile string `toml:"token_file"`

	// The role ID is an identifier, not a secret, so it may be set inline.
	// The secret ID is password-equivalent and has no inline key: the config
	// file never holds confidential material.
	RoleID       string `toml:"role_id"`
	RoleIDFile   string `toml:"role_id_file"`
	SecretIDFile string `toml:"secret_id_file"`

	// Cert login uses the client certificate from
	// BAO_CLIENT_CERT/BAO_CLIENT_KEY. CertRole restricts it to one
	// certificate role; unset, the server tries all of them.
	CertRole string `toml:"cert_role"`

	// The JWT is a bearer credential and has no inline key. JWTRole names
	// the role to log in with; unset, the mount's default role applies.
	JWTFile string `toml:"jwt_file"`
	JWTRole string `toml:"jwt_role"`

	// Mount is the auth method's mount path. Default: the method name.
	// Token auth never logs in, so it takes no mount.
	Mount string `toml:"mount"`
}

// Server configures the credential socket server.
type Server struct {
	// ConnectionTimeout bounds the read from OpenBao and, separately, the
	// write of the payload back to the service manager. A bare integer
	// decodes as nanoseconds, so write it as "15s".
	ConnectionTimeout time.Duration `toml:"connection_timeout"`
}

// Placeholders are the request placeholders a rule's Path, Mount, and Field
// may contain. Package secrets substitutes them per request, so package policy
// has to treat any path segment containing one as a wildcard. Both packages
// depend on this list being complete.
var Placeholders = []string{"{unit}", "{unit_name}", "{prefix}", "{instance}", "{credential}"}

// PlaceholderValues returns what each entry of Placeholders expands to for a
// request from unit for credential. For "foo@bar.service" asking for
// "db-password":
//
//	{unit}       -> foo@bar.service
//	{unit_name}  -> foo@bar
//	{prefix}     -> foo
//	{instance}   -> bar (empty for non-templated units)
//	{credential} -> db-password
func PlaceholderValues(unit, credential string) map[string]string {
	unitName := unit
	if i := strings.LastIndex(unitName, "."); i > 0 {
		unitName = unitName[:i]
	}
	prefix, instance, _ := strings.Cut(unitName, "@")
	return map[string]string{
		"{unit}":       unit,
		"{unit_name}":  unitName,
		"{prefix}":     prefix,
		"{instance}":   instance,
		"{credential}": credential,
	}
}

// PinnedValues returns the placeholder values a rule's globs already determine.
// A glob carrying none of path.Match's metacharacters matches exactly one
// string, so every placeholder fed from it expands to a constant that package
// policy can write into the generated policy in place of a wildcard.
// Placeholders the globs leave free are absent from the result, as are those
// expanding to nothing, which CheckSegments refuses at request time anyway.
func PinnedValues(unitGlob, credentialGlob string) map[string]string {
	unitFixed, credentialFixed := isLiteralGlob(unitGlob), isLiteralGlob(credentialGlob)
	pinned := map[string]string{}
	for p, v := range PlaceholderValues(unitGlob, credentialGlob) {
		fixed := unitFixed
		if p == "{credential}" {
			fixed = credentialFixed
		}
		if fixed && v != "" {
			pinned[p] = v
		}
	}
	return pinned
}

func isLiteralGlob(glob string) bool {
	return !strings.ContainsAny(glob, `*?[\`)
}

// Credential maps requests to a secret in OpenBao. Rules are evaluated in file
// order; the first rule whose Unit and Credential globs both match wins.
// Requests matching no rule are refused.
//
// Path, Field, and Mount support the placeholders in Placeholders.
type Credential struct {
	// Unit is a glob matched against the requesting unit name. Required;
	// granting every unit takes an explicit "*".
	Unit string `toml:"unit"`
	// Credential is a glob matched against the requested credential ID.
	// Default: "*".
	Credential string `toml:"credential"`

	// Backend is "kv" (default) or "raw".
	Backend string `toml:"backend"`
	// Mount is the KV mount point. Default: "kv". Unused with "raw".
	Mount string `toml:"mount"`
	// Path is the secret path below the mount, or the full API path for
	// backend = "raw". Required.
	Path string `toml:"path"`

	// Format is "field" (default) or "json".
	Format string `toml:"format"`
	// Field is the key of the secret data to serve when Format is "field".
	// Default: "{credential}".
	Field string `toml:"field"`
}

// CheckSegments rejects an API path with an empty, ".", or ".." segment, which
// could make URL normalization on the server resolve the read to a secret the
// rule never granted. Package secrets applies it after placeholder expansion,
// where the values come from the requesting side; a literal path carrying one
// is rejected here because it could never serve anything anyway.
func CheckSegments(what, p string) error {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%s %q has an empty, %q, or %q segment", what, p, ".", "..")
		}
	}
	return nil
}

// CheckPolicyWildcards rejects a literal path carrying one of the wildcards
// OpenBao's policy syntax recognizes: "+" matches any one segment, and a
// trailing "*" matches any suffix. Package policy writes a rule's path into the
// generated policy, while package secrets requests it verbatim, so a rule
// carrying either grants a subtree it can never read a secret from. Unit and
// credential globs are unaffected; only the path is shared with the policy.
func CheckPolicyWildcards(what, p string) error {
	var found string
	switch {
	case strings.HasSuffix(p, "*"):
		found = "*"
	case slices.Contains(strings.Split(p, "/"), "+"):
		found = "+"
	default:
		return nil
	}
	return fmt.Errorf("%s %q contains %q, a wildcard in an OpenBao policy; the daemon reads the path verbatim, so the rule would grant far more than it can serve", what, p, found)
}

// Parse decodes, applies defaults to, and validates a configuration.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown configuration keys: %v", undecoded)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.OpenBao.Auth.Method == "" {
		c.OpenBao.Auth.Method = AuthToken
	}
	if c.OpenBao.Auth.Method != AuthToken && c.OpenBao.Auth.Mount == "" {
		c.OpenBao.Auth.Mount = c.OpenBao.Auth.Method
	}

	if c.Server.ConnectionTimeout == 0 {
		c.Server.ConnectionTimeout = 15 * time.Second
	}

	for i := range c.Credentials {
		r := &c.Credentials[i]
		if r.Credential == "" {
			r.Credential = "*"
		}
		if r.Backend == "" {
			r.Backend = BackendKV
		}
		if r.Format == "" {
			r.Format = FormatField
		}
		if r.Backend == BackendKV && r.Mount == "" {
			r.Mount = "kv"
		}
		if r.Format == FormatField && r.Field == "" {
			r.Field = "{credential}"
		}
	}
}

func (c *Config) validate() error {
	a := c.OpenBao.Auth
	switch a.Method {
	case AuthToken, AuthAppRole, AuthCert, AuthJWT:
	default:
		return fmt.Errorf("openbao.auth: unknown method %q (expected %q, %q, %q, or %q)", a.Method, AuthToken, AuthAppRole, AuthCert, AuthJWT)
	}
	if a.Method != AuthToken && a.TokenFile != "" {
		return fmt.Errorf("openbao.auth: token options set but method is %q", a.Method)
	}
	if a.Method != AuthAppRole && (a.RoleID != "" || a.RoleIDFile != "" || a.SecretIDFile != "") {
		return fmt.Errorf("openbao.auth: approle options set but method is %q", a.Method)
	}
	if a.Method != AuthCert && a.CertRole != "" {
		return fmt.Errorf("openbao.auth: cert options set but method is %q", a.Method)
	}
	if a.Method != AuthJWT && (a.JWTFile != "" || a.JWTRole != "") {
		return fmt.Errorf("openbao.auth: jwt options set but method is %q", a.Method)
	}
	if a.Method == AuthToken && a.Mount != "" {
		return fmt.Errorf("openbao.auth: mount is set but method is %q", a.Method)
	}
	if a.Method == AuthAppRole {
		if (a.RoleID == "") == (a.RoleIDFile == "") {
			return fmt.Errorf("openbao.auth: exactly one of role_id and role_id_file is required for approle")
		}
		if a.SecretIDFile == "" {
			return fmt.Errorf("openbao.auth: secret_id_file is required for approle (the secret ID is confidential and has no inline key)")
		}
	}
	if a.Method == AuthJWT && a.JWTFile == "" {
		return fmt.Errorf("openbao.auth: jwt_file is required for jwt (the token is confidential and has no inline key)")
	}

	// A bare TOML integer decodes as nanoseconds, so connection_timeout = 15
	// would silently mean 15ns. Nothing that short is a real timeout.
	if d := c.Server.ConnectionTimeout; d < 0 {
		return fmt.Errorf("server: connection_timeout must not be negative")
	} else if d < time.Millisecond {
		return fmt.Errorf("server: connection_timeout %v is too short to be meant; write it as a duration string like \"15s\"", d)
	}

	for i := range c.Credentials {
		if err := c.Credentials[i].validate(); err != nil {
			return fmt.Errorf("credentials[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *Credential) validate() error {
	if r.Unit == "" {
		return fmt.Errorf("unit is required (granting every unit takes an explicit \"*\")")
	}
	if _, err := path.Match(r.Unit, "probe"); err != nil {
		return fmt.Errorf("unit: invalid glob %q", r.Unit)
	}
	if _, err := path.Match(r.Credential, "probe"); err != nil {
		return fmt.Errorf("credential: invalid glob %q", r.Credential)
	}

	switch r.Backend {
	case BackendKV:
		if err := CheckSegments("mount", r.Mount); err != nil {
			return err
		}
		if err := CheckPolicyWildcards("mount", r.Mount); err != nil {
			return err
		}
	case BackendRaw:
		if r.Mount != "" {
			return fmt.Errorf("mount must not be set with backend = %q", BackendRaw)
		}
	default:
		return fmt.Errorf("unknown backend %q (expected %q or %q)", r.Backend, BackendKV, BackendRaw)
	}

	if r.Path == "" {
		return fmt.Errorf("path is required")
	}
	if err := CheckSegments("path", r.Path); err != nil {
		return err
	}
	if err := CheckPolicyWildcards("path", r.Path); err != nil {
		return err
	}

	switch r.Format {
	case FormatField:
	case FormatJSON:
		if r.Field != "" {
			return fmt.Errorf("field must not be set with format = %q", FormatJSON)
		}
	default:
		return fmt.Errorf("unknown format %q (expected %q or %q)", r.Format, FormatField, FormatJSON)
	}
	return nil
}
