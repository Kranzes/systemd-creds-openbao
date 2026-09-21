// Package policy renders a credential rule list as the OpenBao policy the
// daemon's own token needs to serve those rules. A placeholder whose value the
// rule's globs pin is written out literally. One that is still free becomes a
// single-segment wildcard, which is the only way the policy grants more than
// the rules reach.
package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
)

const header = `# OpenBao policy for systemd-creds-openbao, generated with -print-policy.
# A placeholder the rule's globs leave free becomes "+", OpenBao's
# single-segment wildcard. See
# https://github.com/kranzes/systemd-creds-openbao/blob/master/docs/cli.md#-print-policy
`

const selfHeader = `
# The token the daemon itself holds. The "default" policy already grants these
# three, so they matter for a token created with -no-default-policy or a role
# with token_no_default_policy = true.
`

const secretsHeader = `
# The secrets the credential rules read.
`

// Grant is one path the generated policy allows the daemon's token.
type Grant struct {
	// Path is the OpenBao policy path, where "+" is a single-segment wildcard.
	Path string
	// Capabilities are the OpenBao capabilities granted on Path.
	Capabilities []string
	// Widened reports that a segment mixing a placeholder with literal text had
	// to become a whole wildcard, granting more than the rules can read.
	Widened bool
}

// SelfGrants returns what the daemon needs on its own token, whatever the
// rules are. Package bao reads lookup-self to check the token at startup and
// to tell a refused read from a rejected token, updates renew-self to keep the
// token alive, and updates revoke-self when a reload or shutdown drops it.
func SelfGrants() []Grant {
	return []Grant{
		{Path: "auth/token/lookup-self", Capabilities: []string{"read"}},
		{Path: "auth/token/renew-self", Capabilities: []string{"update"}},
		{Path: "auth/token/revoke-self", Capabilities: []string{"update"}},
	}
}

// Grants returns the paths rules need, deduplicated, in the order the rules
// first ask for them. Generate renders these. Callers that want to reason about
// what the policy allows should read them rather than parse the HCL.
func Grants(rules []config.Credential) []Grant {
	at := map[string]int{}
	var out []Grant
	for _, r := range rules {
		p, widened := policyPath(r)
		if i, seen := at[p]; seen {
			out[i].Widened = out[i].Widened || widened
			continue
		}
		at[p] = len(out)
		out = append(out, Grant{Path: p, Capabilities: []string{"read"}, Widened: widened})
	}
	return out
}

// Generate returns an HCL policy covering rules and the daemon's own token,
// ready for "bao policy write".
func Generate(rules []config.Credential) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString(selfHeader)
	for _, g := range SelfGrants() {
		writeGrant(&b, g)
	}
	b.WriteString(secretsHeader)
	for _, g := range Grants(rules) {
		writeGrant(&b, g)
	}
	return b.String()
}

// writeGrant writes one grant as an HCL path block.
func writeGrant(b *strings.Builder, g Grant) {
	b.WriteString("\n")
	if g.Widened {
		b.WriteString("# NOTE: a placeholder shares this segment with literal text, so it is widened.\n")
	}
	quoted := make([]string, len(g.Capabilities))
	for i, c := range g.Capabilities {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	fmt.Fprintf(b, "path %q {\n  capabilities = [%s]\n}\n", g.Path, strings.Join(quoted, ", "))
}

// policyPath returns the policy path a rule reads, and whether a segment had
// to be widened past what the rule matches to express it.
func policyPath(r config.Credential) (path string, widened bool) {
	read := r.Path
	if r.Backend == config.BackendKV {
		read = r.Mount + "/data/" + r.Path
	}

	// A rule matching one unit and one credential ID resolves to one path, so
	// substituting what its globs pin keeps those segments literal instead of
	// granting a wildcard for a value that can only take one form.
	expand := config.Replacer(config.PinnedValues(r.Unit, r.Credential))

	segments := strings.Split(read, "/")
	for i, seg := range segments {
		seg = expand.Replace(seg)
		segments[i] = seg
		if !hasPlaceholder(seg) {
			continue
		}
		// Neither unit names nor credential IDs can contain a slash, so a
		// segment that is nothing but a placeholder is exactly a "+".
		// Anything else is widened.
		widened = widened || !slices.Contains(config.Placeholders, seg)
		segments[i] = "+"
	}
	return strings.Join(segments, "/"), widened
}

func hasPlaceholder(s string) bool {
	return slices.ContainsFunc(config.Placeholders, func(p string) bool {
		return strings.Contains(s, p)
	})
}
