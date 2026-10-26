# Entity Relationship Model (Proposed)

```mermaid
erDiagram
 TENANT ||--o{ PROJECT : owns
 PROJECT ||--o{ AGENT : enrolls
 PROJECT ||--o{ ENGAGEMENT_SCOPE : defines
 PROJECT ||--o{ TASK : contains
 PROJECT ||--o{ EVIDENCE : retains
 PROJECT ||--o{ AUDIT_EVENT : records
 AGENT ||--o{ AGENT_CERTIFICATE : possesses
 AGENT ||--o{ AGENT_SESSION : starts
 AGENT ||--o{ MESSAGE : originates
 AGENT ||--o{ ELECTION_MEMBERSHIP : participates
 ELECTION_DOMAIN ||--o{ ELECTION_MEMBERSHIP : includes
 PLUGIN ||--o{ PLUGIN_RELEASE : publishes
 PLUGIN_RELEASE ||--o{ AGENT_PLUGIN : installed_on
 AGENT ||--o{ AGENT_PLUGIN : reports
 TASK ||--o{ EVIDENCE : produces
 MESSAGE ||--o{ DELIVERY_RECEIPT : acknowledged_by
 TENANT {
   uuid tenant_id PK
   string name
 }
 PROJECT {
   uuid project_id PK
   uuid tenant_id FK
   string status
 }
 AGENT {
   uuid agent_id PK
   uuid project_id FK
   string state
 }
 AGENT_CERTIFICATE {
   uuid certificate_id PK
   uuid agent_id FK
   string serial
   datetime expires_at
   string revocation_state
 }
 AGENT_SESSION {
   uuid session_id PK
   uuid agent_id FK
   datetime connected_at
 }
 ENGAGEMENT_SCOPE {
   uuid scope_id PK
   uuid project_id FK
   string definition
 }
 TASK {
   uuid task_id PK
   uuid project_id FK
   string status
 }
 EVIDENCE {
   uuid evidence_id PK
   uuid project_id FK
   uuid task_id FK
   string sha256
   string object_key
 }
 MESSAGE {
   uuid message_id PK
   uuid agent_id FK
   int sequence_no
   string payload_hash
 }
 DELIVERY_RECEIPT {
   uuid receipt_id PK
   uuid message_id FK
   string receipt_stage
 }
 ELECTION_DOMAIN {
   uuid domain_id PK
   int membership_version
 }
 ELECTION_MEMBERSHIP {
   uuid membership_id PK
   uuid domain_id FK
   uuid agent_id FK
   boolean voter
 }
 PLUGIN {
   uuid plugin_id PK
   string publisher
 }
 PLUGIN_RELEASE {
   uuid release_id PK
   uuid plugin_id FK
   string version
   string digest
 }
 AGENT_PLUGIN {
   uuid installed_id PK
   uuid agent_id FK
   uuid release_id FK
   string state
 }
 AUDIT_EVENT {
   uuid audit_id PK
   uuid project_id FK
   string event_digest
   datetime recorded_at
 }
```

Tenant and project IDs are immutable authorization attributes. All foreign-key associations must be enforced; object-store keys do not replace relational custody metadata. Append-only audit and receipt histories must not be edited in place. Versioned report schemas are independent of storage schema.
