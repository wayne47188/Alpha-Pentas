# Architecture and Deployment

## Physical deployment / trust boundaries

```mermaid
flowchart TB
 subgraph OP["Operator Workstation"]
  WEB["React Browser"]
  CLI["Go CLI"]
 end
 subgraph CONTROL["Management Infrastructure"]
  API["Go Management Server / API"]
  IAM["Enrollment / Identity / Policy"]
  AUD["Audit + Evidence Ingest"]
  DB[("PostgreSQL")]
  OBJ[("S3-compatible Evidence Store")]
  REG["Signed Plugin Registry"]
 end
 subgraph CUSTOMER["Authorized Customer Environment"]
  EA["Go Agent A"]
  EB["Go Agent B"]
  EC["Go Agent C"]
 end
 WEB -->|HTTPS| API
 CLI -->|Authenticated API| API
 API --> IAM
 API --> AUD
 AUD --> DB
 AUD --> OBJ
 REG --> API
 EA <-->|gRPC mTLS| API
 EB <-->|Authenticated peer channel| EA
 EC <-->|Authenticated peer channel| EA
```

All roles run one Agent binary. Leadership and manager-reachability are independent; peer membership is signed by Manager. Diagram shows illustrative connectivity, not unrestricted network reachability.

## Framework layering

```mermaid
flowchart TB
 CON["React Console + Go CLI"] --> API["Go API / Authorization"]
 API --> APP["Task / Plugin / Audit / Evidence Services"]
 APP --> MSG["Protobuf Message Contract + ACK / Dedup"]
 MSG --> TRANS["Transport Abstraction"]
 TRANS --> GRPC["gRPC bidirectional streaming / mTLS"]
 GRPC --> CORE["Go Agent Core"]
 CORE --> P["Plugin Manager / Supervisor / Capability Broker"]
 P --> IPC["Local gRPC IPC"]
 IPC --> GO["Go Plugin"]
 IPC --> PY["Python Plugin"]
 IPC --> OTHER["Other compatible plugin"]
```

## Core boundaries
Agent may persist identity, election safety metadata, installed plugin packages and limited encrypted spool files; it must not host a system-log database. Manager alone durably stores canonical evidence and operational audit. Plugin signing keys stay off endpoints.

## Data flow
```mermaid
sequenceDiagram
 participant E as Agent
 participant R as Relay (if required)
 participant M as Manager
 participant S as Durable Storage
 E->>E: Assign ID / sequence / source signature
 E->>R: Authenticated event
 R-->>E: Relay ACK after receipt
 R->>M: Forward original signed event
 M->>M: Validate source / policy / deduplicate
 M->>S: Commit
 S-->>M: Durable confirmation
 M-->>E: Final ACK via approved path
```

Relay ACK never implies durable Manager receipt. During outage, bounded encrypted spool may lose messages on capacity exhaustion and must emit gap alerts. Full TCP session migration is not promised.

## Security controls
Written engagement scopes; per-tenant separation; authenticated operator; authorization before tasks; least-privilege plugin processes; explicit capability grants; immutable audit archives; expiry, cancellation and emergency-stop support.
