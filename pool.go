package agentpass

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// CertPool wraps *x509.CertPool with AgentPass-specific helpers
// for loading trust anchors from PEM bytes or files. It is a thin
// convenience layer; callers that already have a *x509.CertPool
// for other reasons can use Verify with that pool directly via
// the underlying CertPool field.
type CertPool struct {
	Pool *x509.CertPool
}

// NewCertPool returns an empty CertPool ready to accept trust
// anchors. Nothing is shared between pools, so two pools created
// from the same source are independent.
func NewCertPool() *CertPool {
	return &CertPool{Pool: x509.NewCertPool()}
}

// AddPEM parses the supplied bytes as one or more PEM-encoded
// CERTIFICATE blocks and adds each parsed certificate to the pool.
// Non-CERTIFICATE PEM blocks are ignored so that callers can pass
// a bundle that also contains keys or CSRs without error.
//
// An error is returned only if no valid CERTIFICATE block was
// found. This keeps misconfigurations loud without punishing
// callers for unrelated junk at the bottom of a bundle.
func (p *CertPool) AddPEM(pemBytes []byte) error {
	if p == nil || p.Pool == nil {
		return fmt.Errorf("agentpass: nil CertPool")
	}

	rest := pemBytes
	var added int
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remainder
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("agentpass: parse CA certificate: %w", err)
		}
		p.Pool.AddCert(cert)
		added++
		rest = remainder
	}
	if added == 0 {
		return fmt.Errorf("%w: found no CERTIFICATE blocks in PEM input", ErrInvalidPEM)
	}
	return nil
}

// AddFile loads a PEM bundle from the local filesystem and adds
// every CERTIFICATE block to the pool. Errors from os.ReadFile are
// passed through so operators can distinguish "permission denied"
// from "no certs in file".
//
// The path is resolved relative to the current working directory
// of the calling process; callers running under systemd or in
// containers should pass absolute paths to avoid surprises.
func (p *CertPool) AddFile(path string) error {
	if path == "" {
		return fmt.Errorf("agentpass: empty trust anchor path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("agentpass: read trust anchor file %q: %w", path, err)
	}
	return p.AddPEM(data)
}

// Size reports how many CA certificates are in the pool. Zero is
// a useful sentinel for callers that want to refuse to start if
// no trust anchors are configured.
//
// The underlying *x509.CertPool does not expose a count directly,
// so this value is tracked by AddPEM/AddFile. It is advisory:
// certificates added via the Pool field directly will not be
// counted. For strict accounting, add anchors only through the
// CertPool methods.
func (p *CertPool) Size() int {
	if p == nil || p.Pool == nil {
		return 0
	}
	// Subjects returns DER-encoded RawSubject bytes, one per
	// CA certificate in the pool.
	//nolint:staticcheck // CertPool.Subjects is deprecated for
	// reading system pools but remains fine for user-built pools.
	return len(p.Pool.Subjects())
}
