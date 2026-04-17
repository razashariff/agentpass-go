// Package testca builds AgentPass-shaped certificate bundles in
// memory for tests. It mirrors the DER extension layout produced
// by aptaas/pki.js so that the verifier is exercised against the
// exact wire format it will see in production.
//
// This package is deliberately test-only. Production code MUST NOT
// import it; reflection-based or init-time behaviour in this
// package is acceptable only because it lives under internal/.
package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Extension OIDs -- mirror github.com/razashariff/agentpass-go/extensions.go.
var (
	OIDAgentTrustLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	OIDAgentScope      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	OIDAgentIssuer     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}
)

// Bundle is a throwaway CA plus one agent certificate, suitable
// for a single test. Each test gets a fresh Bundle so state cannot
// leak between test cases.
type Bundle struct {
	CAKey      *ecdsa.PrivateKey
	CACert     *x509.Certificate
	CAPEM      []byte
	AgentKey   *ecdsa.PrivateKey
	AgentCert  *x509.Certificate
	AgentPEM   []byte
}

// AgentOptions controls the contents of the agent certificate that
// Build emits. Zero values produce a sensible L2 agent valid for 24h.
type AgentOptions struct {
	CommonName string
	TrustLevel int
	Scopes     []string
	IssuerID   string
	NotBefore  time.Time
	NotAfter   time.Time

	// OmitTrust, OmitScope, OmitIssuer skip the corresponding
	// AgentPass custom extension. Used by tests that want to
	// assert on ErrMissingAgentExtensions.
	OmitTrust  bool
	OmitScope  bool
	OmitIssuer bool

	// BadTrustValue, if non-empty, overrides the normal "L<n>"
	// trust-level payload. Used by tests that want to hit
	// ErrInvalidTrustLevel.
	BadTrustValue string
}

// Build produces a fresh CA + agent pair using the supplied
// options. It panics on crypto errors because test setup failing
// indicates a bug in this helper, not in the code under test.
func Build(opts AgentOptions) Bundle {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("testca: generate CA key: %v", err))
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("testca: generate agent key: %v", err))
	}

	now := time.Now().UTC().Truncate(time.Second)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AgentPass Test CA", Organization: []string{"CyberSecAI Test"}, Country: []string{"GB"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		panic(fmt.Sprintf("testca: create CA cert: %v", err))
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(fmt.Sprintf("testca: parse CA cert: %v", err))
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	cn := opts.CommonName
	if cn == "" {
		cn = "Test Agent (agent-001)"
	}
	scopes := opts.Scopes
	if scopes == nil {
		scopes = []string{"payments", "sanctions:search"}
	}
	issuerID := opts.IssuerID
	if issuerID == "" {
		issuerID = "dev-001"
	}
	nb := opts.NotBefore
	if nb.IsZero() {
		nb = now.Add(-time.Minute)
	}
	na := opts.NotAfter
	if na.IsZero() {
		na = now.Add(24 * time.Hour)
	}

	trustLevel := opts.TrustLevel
	// Assemble custom extensions in the same double-wrapped
	// OCTET STRING form produced by aptaas/pki.js.
	var exts []pkix.Extension
	if !opts.OmitTrust {
		val := fmt.Sprintf("L%d", trustLevel)
		if opts.BadTrustValue != "" {
			val = opts.BadTrustValue
		}
		exts = append(exts, pkix.Extension{Id: OIDAgentTrustLevel, Value: wrapUTF8(val)})
	}
	if !opts.OmitScope {
		exts = append(exts, pkix.Extension{Id: OIDAgentScope, Value: wrapUTF8(joinScopes(scopes))})
	}
	if !opts.OmitIssuer {
		exts = append(exts, pkix.Extension{Id: OIDAgentIssuer, Value: wrapUTF8(issuerID)})
	}

	agentSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		panic(fmt.Sprintf("testca: rand serial: %v", err))
	}
	agentTemplate := &x509.Certificate{
		SerialNumber:          agentSerial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"AgentPass"}, Country: []string{"GB"}},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions:       exts,
		BasicConstraintsValid: true,
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTemplate, caCert, &agentKey.PublicKey, caKey)
	if err != nil {
		panic(fmt.Sprintf("testca: create agent cert: %v", err))
	}
	agentCert, err := x509.ParseCertificate(agentDER)
	if err != nil {
		panic(fmt.Sprintf("testca: parse agent cert: %v", err))
	}
	agentPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentDER})

	return Bundle{
		CAKey:     caKey,
		CACert:    caCert,
		CAPEM:     caPEM,
		AgentKey:  agentKey,
		AgentCert: agentCert,
		AgentPEM:  agentPEM,
	}
}

// wrapUTF8 produces the nested ASN.1 OCTET STRING { UTF8String ... }
// shape that aptaas emits. We marshal the inner UTF8String once,
// then wrap the resulting DER bytes in an outer OCTET STRING.
func wrapUTF8(s string) []byte {
	innerDER, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		panic(fmt.Sprintf("testca: marshal UTF8String: %v", err))
	}
	outerDER, err := asn1.Marshal(innerDER)
	if err != nil {
		panic(fmt.Sprintf("testca: marshal OCTET STRING: %v", err))
	}
	return outerDER
}

// joinScopes concatenates scopes with the comma separator used by
// the AgentPass CA. Kept here rather than importing strings to
// make the intent explicit: this matches the exact on-wire format.
func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
