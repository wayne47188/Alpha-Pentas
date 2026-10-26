# P0 Bootstrap

This is **not** an operational C2 implementation. The manager exposes only local health endpoints; the agent prints diagnostics and makes no connections; the CLI performs a development health check.

## Local development

Requires Go 1.23+.

```bash
go test ./...
go run ./manager/cmd/manager
# second terminal
go run ./cli/cmd/alpha
go run ./agent/cmd/agent --version
```

Manager binds to `127.0.0.1:8080` by default. Do not expose its unauthenticated health endpoint publicly. Production authentication, scoped enrollment, gRPC service, signing, audit storage and plugin controls are pending.

The Protobuf schema in `protocol/proto/alpha/v1/envelope.proto` is a draft interface only; generated bindings and transport implementation come after security contract tests. The React console skeleton is separate under `console/`.
