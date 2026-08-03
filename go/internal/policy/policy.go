// Package policy renders a credential rule list as the OpenBao policy the
// daemon's own token needs to serve those rules. A placeholder whose value the
// rule's globs pin is written out literally; one that is still free costs a
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
# https://github.com/kranzes/systemd-creds-openbao#the-daemons-own-policy
`

// Generate returns an HCL policy covering rules, ready for "bao policy write".
func Generate(rules []config.Credential) string {
	// Policy path -> whether a segment had to be widened, plus the order the
	// rules first ask for them in.
	paths := map[string]bool{}
	var order []string
	for _, r := range rules {
		p, widened := policyPath(r)
		if _, seen := paths[p]; !seen {
			order = append(order, p)
		}
		paths[p] = paths[p] || widened
	}

	var b strings.Builder
	b.WriteString(header)
	for _, p := range order {
		b.WriteString("\n")
		if paths[p] {
			b.WriteString("# NOTE: a placeholder shares this segment with literal text; widened.\n")
		}
		fmt.Fprintf(&b, "path %q {\n  capabilities = [\"read\"]\n}\n", p)
	}
	return b.String()
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
	// spending a wildcard on a value that can only take one form.
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
