# Agent gRPC Transport Security

The Manager Agent channel uses a dedicated gRPC listener protected by mutual TLS. It is separate from the health and operator HTTP listeners.

## Required configuration

The Agent gRPC listener is enabled only when its TLS configuration is present. Partial configuration fails closed.

- `ALPHA_AGENT_GRPC_LISTEN` — optional address; defaults to `127.0.0.1:9443` when the listener is enabled.
- `ALPHA_AGENT_TLS_CERT` — Manager server certificate.
- `ALPHA_AGENT_TLS_KEY` — Manager server private key.
- `ALPHA_AGENT_CLIENT_CA` — CA bundle trusted for Agent client certificates.
- `ALPHA_DATABASE_URL` — authoritative Manager PostgreSQL connection.

## Authentication and authorization invariants

1. TLS requires and verifies an Agent client certificate.
2. The certificate must have ClientAuth EKU and exactly one Manager-issued SPIFFE URI:
   `spiffe://alpha-pentas.local/project/<project-id>/agent/<agent-id>`.
3. Certificate fingerprint, Agent state, project state, certificate validity and revocation are re-checked against PostgreSQL.
4. Every bidirectional stream supplies exactly one `alpha-project-id` metadata value. The requested project must equal the signed project in the Agent certificate.
5. Established streams are periodically re-checked. Revocation, Agent suspension, project suspension or expiry causes the gRPC interceptor to terminate the stream.
6. TLS handshake success is not treated as permanent authorization.

## Resource limits

The server enforces bounded transport resources:

- maximum receive message: 4 MiB;
- maximum send message: 4 MiB;
- maximum concurrent streams: 128;
- HTTP/2 keepalive enforcement and idle connection limits.

These are transport ceilings, not plugin payload limits. Large evidence or file transfer protocols should use chunking and application-level quotas.

## Bootstrap service

`alpha.v1.AgentControl/Connect` is currently a minimal bidirectional liveness/security bootstrap stream using protobuf Empty messages. It intentionally does not implement command execution, evidence collection or plugin transfer. Future protocol messages must remain behind the same mTLS interceptor and add action-specific authorization and payload limits.

## Required regression evidence

CI must execute, not skip, the running-Manager PostgreSQL test that proves:

- a valid Agent certificate can open the correct project stream;
- a cross-project stream is denied;
- database revocation terminates an already-established stream;
- a client without an Agent certificate cannot establish the mTLS channel.

CA rotation overlap/retirement is covered by identity verification tests.
