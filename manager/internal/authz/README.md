# Operator authorization boundary

The `authz` package provides a deny-by-default application authorization
check for authenticated operators, tenant/project scope and explicit actions.

It is **not** an identity provider, session authenticator, production DB grant
store or HTTP/gRPC middleware. Applications must obtain principals through a
verified authentication mechanism and must invoke `Check` before privileged
Manager operations. The Agent's enrollment token and mTLS identity are separate
from operator privileges.

No new privileged HTTP endpoint is enabled by these files. Integration of
real grant persistence and authenticated Manager transport is required before
this can be marked complete. Unit tests cover missing authentication, cross
tenant, missing grant, unknown action, backend errors and success.
