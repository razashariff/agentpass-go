# agentpass-go

Go SDK for verifying AgentPass agent identity certificates.

Zero-network, standard-library-only X.509 verification of AgentPass agent certificates with custom trust-level, scope, and issuer extensions.

## Install

```
go get github.com/razashariff/agentpass-go
```

## Usage

```go
package main

import (
	"log"
	"os"

	"github.com/razashariff/agentpass-go"
)

func main() {
	// Load trust anchors (CA certificates you trust)
	pool := agentpass.NewCertPool()
	caPEM, _ := os.ReadFile("/etc/watchman/agentpass-ca.pem")
	if err := pool.AddPEM(caPEM); err != nil {
		log.Fatal(err)
	}

	// Verify an agent certificate from an incoming request
	agentPEM := []byte(getAgentCertFromRequest()) // your HTTP/MCP handler
	verified, err := agentpass.Verify(agentPEM, pool,
		agentpass.WithMinTrust(2),                         // reject L0/L1 agents
		agentpass.WithRequiredScopes("sanctions:search"),   // require specific capability
	)
	if err != nil {
		log.Fatalf("agent rejected: %v", err)
	}

	log.Printf("agent %s (L%d) verified, scopes=%v, issuer=%s",
		verified.AgentID,
		verified.TrustLevel,
		verified.Scopes,
		verified.IssuerID,
	)
}
```

## Architecture

- **No network calls.** Verification is pure local crypto (ECDSA P-256 + SHA-256).
- **Trust anchors in config.** Same model as TLS root CAs. Callers pick which issuers to trust.
- **Self-hostable registry.** Agents can register with agentpass.co.uk (free) or any self-hosted AgentPass registry.
- **Standard library only.** No CGo, no unsafe, no external crypto dependencies.

## Certificate format

AgentPass agents carry X.509 v3 certificates with three custom extensions:

| OID | Name | Example value |
|-----|------|---------------|
| 1.3.6.1.4.1.99999.1.1 | Trust level | "L2" |
| 1.3.6.1.4.1.99999.1.2 | Scopes | "payments,sanctions:search" |
| 1.3.6.1.4.1.99999.1.3 | Issuer ID | "dev-001" |

Certificates are signed by an AgentPass CA using ECDSA with SHA-256 on the P-256 curve.

## Test coverage

```
ok  github.com/razashariff/agentpass-go  coverage: 84.0% of statements
```

20 test cases covering: happy path, expired certs, untrusted CA, tampered signatures, missing extensions, bad trust levels, RSA rejection, min-trust policy, scope gating, pinned time verification.

## License

Apache License 2.0. See LICENSE file.

(c) 2026 CyberSecAI Ltd.
