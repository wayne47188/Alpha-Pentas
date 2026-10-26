# P1 X.509 Agent Certificate Issuer

The `manager/internal/identity` Go package is an independent CSR validator / X.509 client-certificate issuer. The CA certificate and private-key signer must be provisioned externally; the signer is injected into the module.

## Implemented
- Verify CSR signature (proof of possession) and restrict to Ed25519, ECDSA >= P-256 or RSA >= 2048.
- Reject all requested SANs; authenticated Manager attributes determine Agent identity.
- Validate canonical lowercase UUID project and agent identifiers.
- Issue client-auth-only X.509 certificates with URI SAN: `spiffe://alpha-pentas.local/project/<projectUUID>/agent/<agentUUID>`.
- Maximum certificate lifetime 7 days, bounded by issuer CA expiration, random serial and SHA-256 fingerprint.
- Unit tests: validation, cryptographic chain verification, SAN rejection and lifetime limits.

## Critical unfinished integration
- **No authenticated enrollment endpoint** or link from database claim to certificate issue.
- No automatic durable CA provision, key rotation, revocation list, OCSP, audit, policy enforcement or mTLS listener.
- Real CSR issuance must transactionally validate a pending claim and match its stored CSR digest before signing; persist certificate serial/fingerprint and mark `issued`.
- Avoid signing on untrusted public input. CA keys belong in protected server-side key storage / signing service, not Agent binaries.
- This is a tested standalone module, not yet production PKI.
