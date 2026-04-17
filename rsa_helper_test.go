package agentpass_test

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"testing"
)

// The helpers in this file exist solely to support
// TestVerify_RejectsNonECDSACertificate in verify_test.go. They
// live in a separate file so that the main test file stays focused
// on verifier behaviour rather than on RSA plumbing.

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

func mustBigInt(n int64) *big.Int {
	return big.NewInt(n)
}

func randReader() io.Reader {
	return rand.Reader
}
