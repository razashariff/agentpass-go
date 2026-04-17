// Package agentpass verifies AgentPass agent identity certificates.
//
// AgentPass is an open identity layer for AI agents making regulated
// payments. Each agent holds an ECDSA P-256 X.509 certificate issued
// by a registered AgentPass Certificate Authority. The certificate
// carries three custom extensions describing the agent trust level
// (L0-L4), its authorised scopes, and the issuing developer.
//
// This package is a zero-network Go implementation of the AgentPass
// verification logic. Callers provide a pool of trusted CA
// certificates and a candidate agent certificate; the package
// performs standard X.509 chain verification using the Go standard
// library and extracts the AgentPass trust extensions for the
// caller.
//
// # Minimal example
//
//	pool := agentpass.NewCertPool()
//	if err := pool.AddPEM(caPEM); err != nil {
//	    log.Fatal(err)
//	}
//	agent, err := agentpass.Verify(agentPEM, pool, agentpass.Now())
//	if err != nil {
//	    log.Fatalf("agent rejected: %v", err)
//	}
//	log.Printf("agent %s verified at trust level L%d", agent.AgentID, agent.TrustLevel)
//
// # Design notes
//
//   - No network I/O. Revocation checks (OCSP/CRL) are explicitly
//     out of scope for this package; callers that need them should
//     wrap the verifier with their own revocation pipeline.
//   - No global state. The verifier is safe for concurrent use.
//   - Standard-library crypto only. No reflection, no unsafe, no
//     runtime code generation.
//   - Constant-time cryptographic comparisons are handled by
//     crypto/ecdsa inside the standard library.
package agentpass
