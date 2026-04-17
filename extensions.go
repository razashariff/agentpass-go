package agentpass

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// AgentPass custom X.509 extension OIDs.
//
// These match the OIDs emitted by the AgentPass CA in
// aptaas/pki.js (see OID.agentTrust etc.). They are registered
// under the CyberSecAI private enterprise number arc.
var (
	oidAgentTrustLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidAgentScope      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	oidAgentIssuer     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}
)

// maxExtensionBytes caps the raw extension value size to defend
// against adversarial certificates that embed excessively large
// payloads in an attempt to exhaust memory during parsing. A
// well-formed AgentPass extension is at most a few bytes.
const maxExtensionBytes = 4096

// agentExtensions is an internal parsed view of the three AgentPass
// extensions that must be present on every agent certificate.
type agentExtensions struct {
	TrustLevel int
	Scopes     []string
	IssuerID   string
}

// parseAgentExtensions walks the certificate's Extensions slice,
// extracts the three AgentPass custom extensions, and returns them
// in a structured form. It returns ErrMissingAgentExtensions if any
// of the three are absent.
func parseAgentExtensions(cert *x509.Certificate) (agentExtensions, error) {
	var out agentExtensions
	var haveTrust, haveScope, haveIssuer bool

	for _, ext := range cert.Extensions {
		if len(ext.Value) > maxExtensionBytes {
			return out, fmt.Errorf("agentpass: extension %s exceeds %d byte limit", ext.Id.String(), maxExtensionBytes)
		}
		switch {
		case ext.Id.Equal(oidAgentTrustLevel):
			level, err := parseTrustLevel(ext.Value)
			if err != nil {
				return out, err
			}
			out.TrustLevel = level
			haveTrust = true
		case ext.Id.Equal(oidAgentScope):
			scopes, err := parseUTF8OctetString(ext.Value)
			if err != nil {
				return out, fmt.Errorf("agentpass: scope extension: %w", err)
			}
			out.Scopes = splitScopes(scopes)
			haveScope = true
		case ext.Id.Equal(oidAgentIssuer):
			issuer, err := parseUTF8OctetString(ext.Value)
			if err != nil {
				return out, fmt.Errorf("agentpass: issuer extension: %w", err)
			}
			out.IssuerID = issuer
			haveIssuer = true
		}
	}

	if !haveTrust || !haveScope || !haveIssuer {
		return out, ErrMissingAgentExtensions
	}
	return out, nil
}

// parseTrustLevel reads an ASN.1 OCTET STRING wrapping a UTF8
// string of the form "L0".."L4" and returns the numeric level.
// Any other shape is rejected with ErrInvalidTrustLevel to keep
// downstream comparisons simple.
func parseTrustLevel(der []byte) (int, error) {
	raw, err := parseUTF8OctetString(der)
	if err != nil {
		return 0, ErrInvalidTrustLevel
	}
	if len(raw) != 2 || raw[0] != 'L' {
		return 0, ErrInvalidTrustLevel
	}
	n, err := strconv.Atoi(string(raw[1]))
	if err != nil || n < 0 || n > 4 {
		return 0, ErrInvalidTrustLevel
	}
	return n, nil
}

// parseUTF8OctetString unwraps an ASN.1 OCTET STRING containing a
// UTF8String. AgentPass emits extension values as nested
// OCTET STRING { UTF8String ... }, matching the wire shape produced
// by aptaas/pki.js::derOctetString(derUtf8(...)).
func parseUTF8OctetString(der []byte) (string, error) {
	var outer []byte
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return "", fmt.Errorf("agentpass: expected outer OCTET STRING: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("agentpass: trailing bytes after outer OCTET STRING")
	}

	var inner string
	rest, err = asn1.UnmarshalWithParams(outer, &inner, "utf8")
	if err != nil {
		return "", fmt.Errorf("agentpass: expected inner UTF8String: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("agentpass: trailing bytes after inner UTF8String")
	}
	return inner, nil
}

// splitScopes parses the comma-separated scope string emitted by
// the CA into a slice of trimmed scope tokens. Empty tokens are
// dropped so that trailing commas and accidental whitespace do not
// produce blank entries.
func splitScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		return nil
	}
	return scopes
}
