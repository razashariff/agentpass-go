package agentpass

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Agent is the parsed, unverified view of an AgentPass agent
// certificate. Callers should only trust fields on an Agent that
// came back from Verify; ParseCertificate returns an Agent that has
// been syntactically validated but whose signature has NOT been
// checked against any trust anchor.
type Agent struct {
	// X509 is the underlying certificate. Retained so callers that
	// want to do additional inspection (fingerprinting, pinning,
	// custom extension handling) can do so without re-parsing.
	X509 *x509.Certificate

	// AgentID is the stable identifier embedded in the certificate
	// Common Name. In AgentPass the CN is formatted as
	// "<agentName> (<agentID>)" and AgentID is the parenthesised
	// portion.
	AgentID string

	// AgentName is the display name embedded in the certificate
	// Common Name (the portion before the parenthesised ID).
	AgentName string

	// TrustLevel is the L0-L4 tier recorded in the custom
	// trust-level extension.
	TrustLevel int

	// Scopes is the list of authorised capabilities recorded in
	// the custom scope extension. May be empty.
	Scopes []string

	// IssuerID is the developer/issuer identifier recorded in the
	// custom issuer extension. This is a free-form string chosen by
	// the CA and is not the same thing as the certificate issuer DN.
	IssuerID string

	// Serial is the certificate serial number rendered as decimal.
	Serial string

	// NotBefore and NotAfter mirror the X.509 validity window.
	NotBefore time.Time
	NotAfter  time.Time
}

// Verified is returned by Verify when a certificate has been
// syntactically parsed, cryptographically chain-verified against a
// trust anchor, and confirmed to carry the required AgentPass
// extensions.
type Verified struct {
	Agent

	// Chains holds the verified certificate chains returned by the
	// standard library verifier. It is useful for callers that want
	// to log or inspect which trust anchor accepted the agent.
	Chains [][]*x509.Certificate
}

// HasScope reports whether the agent's scope list contains the
// named capability. Comparison is case-sensitive to match the
// format emitted by aptaas/pki.js.
func (a *Agent) HasScope(scope string) bool {
	for _, s := range a.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// agentIDRegexp pulls the "(<id>)" suffix out of the certificate
// Common Name. The CA constructs Common Name as
// "<agentName> (<agentID>)"; callers occasionally issue names that
// contain additional parentheses, so the pattern matches the last
// parenthesised group rather than the first.
var agentIDRegexp = regexp.MustCompile(`^(.*?)\s*\(([^()]+)\)\s*$`)

// splitCommonName separates the agent name and agent ID from the
// raw CN field. If the CN does not contain a trailing parenthesised
// identifier, the entire CN is treated as the agent name and the
// agent ID is reported as empty.
func splitCommonName(cn string) (name, id string) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "", ""
	}
	m := agentIDRegexp.FindStringSubmatch(cn)
	if m == nil {
		return cn, ""
	}
	return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
}

// serialString renders the certificate serial number in the same
// decimal shape that the AgentPass CA writes into its metadata
// files, keeping audit logs consistent across the two stacks.
func serialString(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return cert.SerialNumber.Text(10)
}

// newAgentFromCert builds an Agent from a parsed x509.Certificate
// plus the already-extracted AgentPass extensions. It is used both
// by ParseCertificate (no trust check) and by Verify (after chain
// verification succeeds) so that the two entry points return a
// consistent view.
func newAgentFromCert(cert *x509.Certificate, ext agentExtensions) (*Agent, error) {
	if cert == nil {
		return nil, fmt.Errorf("agentpass: nil certificate")
	}
	name, id := splitCommonName(cert.Subject.CommonName)
	return &Agent{
		X509:       cert,
		AgentID:    id,
		AgentName:  name,
		TrustLevel: ext.TrustLevel,
		Scopes:     ext.Scopes,
		IssuerID:   ext.IssuerID,
		Serial:     serialString(cert),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
	}, nil
}
