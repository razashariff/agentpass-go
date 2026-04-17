package agentpass_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/razashariff/agentpass-go"
	"github.com/razashariff/agentpass-go/internal/testca"
)

// fixedTime is a helper that returns a constant time source for
// tests that need to pin the verifier clock.
func fixedTime(t time.Time) agentpass.TimeSource {
	return func() time.Time { return t }
}

// poolFromCA builds a CertPool containing only the test bundle's
// CA. Every test that verifies successfully runs through this
// helper so regressions in pool setup surface as a single
// contained failure rather than being duplicated across tests.
func poolFromCA(t *testing.T, caPEM []byte) *agentpass.CertPool {
	t.Helper()
	pool := agentpass.NewCertPool()
	if err := pool.AddPEM(caPEM); err != nil {
		t.Fatalf("add trust anchor: %v", err)
	}
	return pool
}

func TestVerify_Happy(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := poolFromCA(t, bundle.CAPEM)

	verified, err := agentpass.Verify(bundle.AgentPEM, pool)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want %q", verified.AgentID, "agent-001")
	}
	if verified.AgentName != "Test Agent" {
		t.Errorf("AgentName = %q, want %q", verified.AgentName, "Test Agent")
	}
	if verified.TrustLevel != 2 {
		t.Errorf("TrustLevel = %d, want 2", verified.TrustLevel)
	}
	if !verified.HasScope("payments") {
		t.Errorf("expected agent to have 'payments' scope, got %v", verified.Scopes)
	}
	if !verified.HasScope("sanctions:search") {
		t.Errorf("expected agent to have 'sanctions:search' scope, got %v", verified.Scopes)
	}
	if verified.IssuerID != "dev-001" {
		t.Errorf("IssuerID = %q, want dev-001", verified.IssuerID)
	}
	if len(verified.Chains) == 0 {
		t.Error("expected at least one verified chain")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	now := time.Now()
	bundle := testca.Build(testca.AgentOptions{
		TrustLevel: 2,
		NotBefore:  now.Add(-48 * time.Hour),
		NotAfter:   now.Add(-1 * time.Hour),
	})
	pool := poolFromCA(t, bundle.CAPEM)

	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_RejectsNotYetValid(t *testing.T) {
	now := time.Now()
	bundle := testca.Build(testca.AgentOptions{
		TrustLevel: 2,
		NotBefore:  now.Add(time.Hour),
		NotAfter:   now.Add(24 * time.Hour),
	})
	pool := poolFromCA(t, bundle.CAPEM)

	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrExpired) {
		t.Fatalf("expected ErrExpired for not-yet-valid, got %v", err)
	}
}

func TestVerify_RejectsUntrustedCA(t *testing.T) {
	// Build two independent bundles so the CAs are different.
	bundleA := testca.Build(testca.AgentOptions{TrustLevel: 2})
	bundleB := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := poolFromCA(t, bundleA.CAPEM) // trust A only
	_, err := agentpass.Verify(bundleB.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrChainInvalid) {
		t.Fatalf("expected ErrChainInvalid, got %v", err)
	}
}

func TestVerify_RejectsTamperedCertificate(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := poolFromCA(t, bundle.CAPEM)

	// Flip the last byte of the DER body. The PEM still decodes
	// but the signature check fails.
	block, _ := pem.Decode(bundle.AgentPEM)
	if block == nil {
		t.Fatal("decode original agent PEM")
	}
	tampered := make([]byte, len(block.Bytes))
	copy(tampered, block.Bytes)
	tampered[len(tampered)-1] ^= 0x01
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tampered})

	_, err := agentpass.Verify(tamperedPEM, pool)
	if err == nil {
		t.Fatal("expected verification error on tampered cert")
	}
}

func TestVerify_RejectsMissingTrustLevelExtension(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{OmitTrust: true})
	pool := poolFromCA(t, bundle.CAPEM)

	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrMissingAgentExtensions) {
		t.Fatalf("expected ErrMissingAgentExtensions, got %v", err)
	}
}

func TestVerify_RejectsMissingScopeExtension(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{OmitScope: true})
	pool := poolFromCA(t, bundle.CAPEM)

	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrMissingAgentExtensions) {
		t.Fatalf("expected ErrMissingAgentExtensions, got %v", err)
	}
}

func TestVerify_RejectsMissingIssuerExtension(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{OmitIssuer: true})
	pool := poolFromCA(t, bundle.CAPEM)

	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrMissingAgentExtensions) {
		t.Fatalf("expected ErrMissingAgentExtensions, got %v", err)
	}
}

func TestVerify_RejectsBadTrustLevelFormat(t *testing.T) {
	// Each string here is a deliberately malformed trust-level
	// payload that should be rejected. An empty-string case is not
	// included because the testca builder treats empty as "use the
	// default L<n>" rather than as an actual override.
	cases := []string{"L", "L5", "LX", "0", "level-2", "LL2"}
	for _, bad := range cases {
		t.Run("bad="+bad, func(t *testing.T) {
			bundle := testca.Build(testca.AgentOptions{BadTrustValue: bad})
			pool := poolFromCA(t, bundle.CAPEM)
			_, err := agentpass.Verify(bundle.AgentPEM, pool)
			if !errors.Is(err, agentpass.ErrInvalidTrustLevel) && !errors.Is(err, agentpass.ErrMissingAgentExtensions) {
				t.Fatalf("expected ErrInvalidTrustLevel, got %v", err)
			}
		})
	}
}

func TestVerify_RejectsEmptyPool(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := agentpass.NewCertPool()
	_, err := agentpass.Verify(bundle.AgentPEM, pool)
	if !errors.Is(err, agentpass.ErrNoTrustAnchors) {
		t.Fatalf("expected ErrNoTrustAnchors, got %v", err)
	}
}

func TestVerify_RejectsNonCertificatePEM(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := poolFromCA(t, bundle.CAPEM)
	bogus := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{0x30, 0x00}})
	_, err := agentpass.Verify(bogus, pool)
	if !errors.Is(err, agentpass.ErrInvalidPEM) {
		t.Fatalf("expected ErrInvalidPEM, got %v", err)
	}
}

func TestVerify_RejectsGarbageInput(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	pool := poolFromCA(t, bundle.CAPEM)
	_, err := agentpass.Verify([]byte("not pem at all"), pool)
	if !errors.Is(err, agentpass.ErrInvalidPEM) {
		t.Fatalf("expected ErrInvalidPEM, got %v", err)
	}
}

func TestVerify_WithMinTrust_Accepts(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 3})
	pool := poolFromCA(t, bundle.CAPEM)
	_, err := agentpass.Verify(bundle.AgentPEM, pool, agentpass.WithMinTrust(2))
	if err != nil {
		t.Fatalf("expected verification to succeed, got %v", err)
	}
}

func TestVerify_WithMinTrust_Rejects(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 1})
	pool := poolFromCA(t, bundle.CAPEM)
	_, err := agentpass.Verify(bundle.AgentPEM, pool, agentpass.WithMinTrust(2))
	if !errors.Is(err, agentpass.ErrTrustLevelBelowMinimum) {
		t.Fatalf("expected ErrTrustLevelBelowMinimum, got %v", err)
	}
}

func TestVerify_WithRequiredScopes_Accepts(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{
		TrustLevel: 2,
		Scopes:     []string{"sanctions:search", "payments"},
	})
	pool := poolFromCA(t, bundle.CAPEM)
	_, err := agentpass.Verify(bundle.AgentPEM, pool, agentpass.WithRequiredScopes("sanctions:search"))
	if err != nil {
		t.Fatalf("expected verification to succeed, got %v", err)
	}
}

func TestVerify_WithRequiredScopes_Rejects(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{
		TrustLevel: 2,
		Scopes:     []string{"payments"},
	})
	pool := poolFromCA(t, bundle.CAPEM)
	_, err := agentpass.Verify(bundle.AgentPEM, pool, agentpass.WithRequiredScopes("sanctions:search"))
	if err == nil || !strings.Contains(err.Error(), "sanctions:search") {
		t.Fatalf("expected missing-scope error, got %v", err)
	}
}

func TestVerify_WithTime_Pinned(t *testing.T) {
	now := time.Now()
	bundle := testca.Build(testca.AgentOptions{
		TrustLevel: 2,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(time.Hour),
	})
	pool := poolFromCA(t, bundle.CAPEM)

	// Pin verification clock well past NotAfter -> expired.
	_, err := agentpass.Verify(bundle.AgentPEM, pool, agentpass.WithTime(fixedTime(now.Add(2*time.Hour))))
	if !errors.Is(err, agentpass.ErrExpired) {
		t.Fatalf("expected ErrExpired under pinned time, got %v", err)
	}
}

func TestParseCertificatePEM_ReturnsAgentWithoutVerifying(t *testing.T) {
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 4})
	agent, err := agentpass.ParseCertificatePEM(bundle.AgentPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if agent.TrustLevel != 4 {
		t.Errorf("TrustLevel = %d, want 4", agent.TrustLevel)
	}
	if agent.Serial == "" {
		t.Error("expected non-empty serial")
	}
	if agent.X509 == nil {
		t.Fatal("expected underlying X.509 certificate")
	}
}

func TestCertPool_Size(t *testing.T) {
	pool := agentpass.NewCertPool()
	if got := pool.Size(); got != 0 {
		t.Errorf("empty pool size = %d, want 0", got)
	}
	bundle := testca.Build(testca.AgentOptions{TrustLevel: 2})
	if err := pool.AddPEM(bundle.CAPEM); err != nil {
		t.Fatalf("add PEM: %v", err)
	}
	if got := pool.Size(); got != 1 {
		t.Errorf("pool size after AddPEM = %d, want 1", got)
	}
}

func TestCertPool_AddPEM_RejectsInputWithNoCertificates(t *testing.T) {
	pool := agentpass.NewCertPool()
	err := pool.AddPEM([]byte("-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----\n"))
	if !errors.Is(err, agentpass.ErrInvalidPEM) {
		t.Fatalf("expected ErrInvalidPEM, got %v", err)
	}
}

func TestVerify_RejectsNonECDSACertificate(t *testing.T) {
	// Construct an RSA-signed dummy chain. We build it locally
	// rather than via testca to explicitly cover the algorithm
	// rejection path.
	rsaBundle := buildRSAAgentBundle(t)
	pool := agentpass.NewCertPool()
	if err := pool.AddPEM(rsaBundle.caPEM); err != nil {
		t.Fatalf("add RSA CA: %v", err)
	}
	_, err := agentpass.Verify(rsaBundle.agentPEM, pool)
	if !errors.Is(err, agentpass.ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

// rsaBundle is a tiny local helper for the algorithm-rejection
// test. The agent certificate it returns DOES carry valid
// AgentPass custom extensions so that the Verify call gets past
// extension parsing and reaches the algorithm check.
type rsaBundle struct {
	caPEM    []byte
	agentPEM []byte
}

// rsaAgentExtensions builds a minimal but valid set of AgentPass
// custom extensions so the RSA cert under test is rejected for the
// signature algorithm rather than for missing extensions.
func rsaAgentExtensions(t *testing.T) []pkix.Extension {
	t.Helper()
	wrap := func(s string) []byte {
		inner, err := asn1.MarshalWithParams(s, "utf8")
		if err != nil {
			t.Fatalf("marshal UTF8: %v", err)
		}
		outer, err := asn1.Marshal(inner)
		if err != nil {
			t.Fatalf("marshal OCTET STRING: %v", err)
		}
		return outer
	}
	return []pkix.Extension{
		{Id: testca.OIDAgentTrustLevel, Value: wrap("L2")},
		{Id: testca.OIDAgentScope, Value: wrap("payments")},
		{Id: testca.OIDAgentIssuer, Value: wrap("rsa-issuer")},
	}
}

func buildRSAAgentBundle(t *testing.T) rsaBundle {
	t.Helper()
	caKey := mustGenerateRSAKey(t)
	agentKey := mustGenerateRSAKey(t)

	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          mustBigInt(1),
		Subject:               pkix.Name{CommonName: "RSA Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	caDER, err := x509.CreateCertificate(randReader(), caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create RSA CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	agentTemplate := &x509.Certificate{
		SerialNumber:       mustBigInt(2),
		Subject:            pkix.Name{CommonName: "RSA Agent (rsa-001)"},
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           now.Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions:    rsaAgentExtensions(t),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	agentDER, err := x509.CreateCertificate(randReader(), agentTemplate, caCert, &agentKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create RSA agent: %v", err)
	}
	agentPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentDER})

	return rsaBundle{caPEM: caPEM, agentPEM: agentPEM}
}
