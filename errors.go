package agentpass

import "errors"

// Sentinel errors returned by Verify and the PEM helpers.
//
// Callers can match against these with errors.Is to drive their
// own auditing and rate-limiting decisions without having to
// string-match error messages.
var (
	// ErrInvalidPEM is returned when the input bytes cannot be
	// interpreted as a PEM-encoded X.509 certificate.
	ErrInvalidPEM = errors.New("agentpass: input is not a valid PEM certificate block")

	// ErrNoTrustAnchors is returned when Verify is called with an
	// empty trust anchor pool.
	ErrNoTrustAnchors = errors.New("agentpass: trust anchor pool is empty")

	// ErrChainInvalid is returned when the candidate certificate
	// does not chain to any of the configured trust anchors.
	ErrChainInvalid = errors.New("agentpass: certificate does not chain to any trusted issuer")

	// ErrExpired is returned when the candidate certificate is
	// outside its NotBefore/NotAfter window at verification time.
	ErrExpired = errors.New("agentpass: certificate is expired or not yet valid")

	// ErrMissingAgentExtensions is returned when the candidate
	// certificate chains correctly but does not carry the required
	// AgentPass custom extensions (trust level, scope, issuer).
	ErrMissingAgentExtensions = errors.New("agentpass: certificate lacks required AgentPass extensions")

	// ErrInvalidTrustLevel is returned when the trust-level
	// extension is present but its value cannot be parsed as L0-L4.
	ErrInvalidTrustLevel = errors.New("agentpass: trust-level extension malformed")

	// ErrUnsupportedAlgorithm is returned when the candidate
	// certificate is not signed with the ECDSA + SHA-256 scheme
	// used by AgentPass.
	ErrUnsupportedAlgorithm = errors.New("agentpass: certificate is not ECDSA-SHA256")

	// ErrTrustLevelBelowMinimum is returned by VerifyMinTrust when
	// a certificate verifies successfully but its trust level is
	// below the caller-specified minimum.
	ErrTrustLevelBelowMinimum = errors.New("agentpass: agent trust level below configured minimum")
)
