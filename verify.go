package agentpass

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// TimeSource returns the current time used by the verifier. It is
// an indirection so that tests can pin the verification clock to a
// fixed moment and so that embedders that run in environments with
// unreliable wall clocks can supply their own trusted time source.
//
// The default TimeSource is Now, which simply returns time.Now().
type TimeSource func() time.Time

// Now is the default TimeSource used when callers do not supply
// their own. It is a method rather than a plain time.Now so that
// it can be passed to Verify as a value of type TimeSource without
// an adapter.
func Now() time.Time { return time.Now() }

// VerifyOption configures an individual call to Verify. Options are
// cumulative: pass as many as needed in any order.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	// now is the TimeSource used both for chain validation and for
	// AgentPass-specific expiry checks. If nil, time.Now is used.
	now TimeSource

	// minTrust is the minimum AgentPass trust level the caller will
	// accept. Defaults to 0 (accept any valid agent certificate).
	minTrust int

	// requireScopes lists scopes that must be present on the agent
	// certificate. An agent that verifies cryptographically but
	// does not carry every required scope is rejected.
	requireScopes []string
}

// WithTime pins the verification clock. Useful in tests and in
// embedders that get their time from an authoritative source.
func WithTime(now TimeSource) VerifyOption {
	return func(c *verifyConfig) { c.now = now }
}

// WithMinTrust rejects agents whose trust level is below level.
// Callers typically set this to 2 in production to reject
// unverified (L0) and developer-sandbox (L1) agents.
func WithMinTrust(level int) VerifyOption {
	return func(c *verifyConfig) { c.minTrust = level }
}

// WithRequiredScopes rejects agents that lack any of the listed
// scopes. Useful for Watchman-style integrations that want to
// demand e.g. WithRequiredScopes("sanctions:search") before
// accepting a screening request.
func WithRequiredScopes(scopes ...string) VerifyOption {
	return func(c *verifyConfig) {
		c.requireScopes = append(c.requireScopes, scopes...)
	}
}

// Verify parses a PEM-encoded agent certificate, confirms that it
// chains to a certificate in pool, confirms it is within its
// validity window, confirms it carries the AgentPass custom
// extensions, and (optionally) confirms policy such as minimum
// trust level and required scopes.
//
// On success Verify returns a *Verified containing the agent's
// parsed identity along with the verified certificate chain. On
// failure Verify returns one of the sentinel errors defined in
// errors.go wrapped with additional context using fmt.Errorf %w,
// so callers can use errors.Is to classify failures.
func Verify(pemBytes []byte, pool *CertPool, opts ...VerifyOption) (*Verified, error) {
	cfg := &verifyConfig{now: Now}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.now == nil {
		cfg.now = Now
	}

	if pool == nil || pool.Pool == nil || pool.Size() == 0 {
		return nil, ErrNoTrustAnchors
	}

	cert, err := ParseCertificatePEM(pemBytes)
	if err != nil {
		return nil, err
	}

	now := cfg.now()

	if err := checkValidityWindow(cert.X509, now); err != nil {
		return nil, err
	}
	if err := checkAlgorithm(cert.X509); err != nil {
		return nil, err
	}

	chains, err := cert.X509.Verify(x509.VerifyOptions{
		Roots:       pool.Pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}

	if cfg.minTrust > 0 && cert.TrustLevel < cfg.minTrust {
		return nil, fmt.Errorf("%w (agent=L%d, min=L%d)", ErrTrustLevelBelowMinimum, cert.TrustLevel, cfg.minTrust)
	}

	for _, required := range cfg.requireScopes {
		if !cert.HasScope(required) {
			return nil, fmt.Errorf("agentpass: agent missing required scope %q", required)
		}
	}

	return &Verified{Agent: *cert, Chains: chains}, nil
}

// ParseCertificatePEM decodes a PEM-encoded X.509 certificate and
// returns the syntactically parsed AgentPass view. Chain validity,
// time validity, and trust level are NOT checked; callers that
// want a safe-to-trust result should use Verify instead.
//
// ParseCertificatePEM is exposed primarily for tooling and tests;
// it is not the expected entry point for production code.
func ParseCertificatePEM(pemBytes []byte) (*Agent, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPEM, err)
	}
	ext, err := parseAgentExtensions(cert)
	if err != nil {
		if errors.Is(err, ErrMissingAgentExtensions) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrMissingAgentExtensions, err)
	}
	return newAgentFromCert(cert, ext)
}

// checkValidityWindow enforces that the reference time sits within
// [NotBefore, NotAfter]. It is separate from the full Verify call
// so that callers can get a precise ErrExpired rather than the
// generic chain-verification error the standard library returns
// when validity is out of range.
func checkValidityWindow(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s", ErrExpired, cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// checkAlgorithm rejects certificates that are not signed with
// ECDSA using SHA-256. AgentPass CAs emit exactly this shape, so
// anything else is either a wrong-format issuer or an adversary.
func checkAlgorithm(cert *x509.Certificate) error {
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("%w: got %s", ErrUnsupportedAlgorithm, cert.SignatureAlgorithm)
	}
	return nil
}
