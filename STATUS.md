# Status

Last updated: 2026-11-13

## Working (tested 2026-11-13)
- Canonical JSON with float rejection
- SHA-256 hash-linked receipt chain
- ECDSA P-256 over the receipt digest, KMS-compatible (Prehashed)
- Intent receipt sealed before the statement executes
- Outcome receipt sealed after commit or rollback
- Verifier requiring only the public key
- 10 unit tests passing
- 6 tamper cases, all detected
- Signing in a separate process via HTTP (tested, both modes pass)

## Not built
- KMS-backed signing deployed (class written, never run against AWS)
- Real key isolation (current test runs both processes as one OS user;
  the agent can read signer_key.pem from disk)
- Bypass resistance (agent can open its own DB connection)
- Wire-level interception (this is driver-level)
- Trusted timestamping
- Any client deployment
- Any independent review

## Claims we do not make
immutable · certified · compliant · attested · court-ready · FRE 902 compliant ·
independently verified

## Engagements
None. Pre-revenue. No case studies.