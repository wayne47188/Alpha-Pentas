package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const ProjectMetadataKey = "alpha-project-id"

type agentPeerContextKey struct{}

func AgentPeerFromContext(ctx context.Context) (identity.AgentPeer, bool) {
	value, ok := ctx.Value(agentPeerContextKey{}).(identity.AgentPeer)
	return value, ok && value.ProjectID != "" && value.AgentID != ""
}

type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s contextServerStream) Context() context.Context {
	return s.ctx
}

func tlsStateFromContext(ctx context.Context) (tls.ConnectionState, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return tls.ConnectionState{}, ErrAgentTLS
	}
	switch info := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		return info.State, nil
	case *credentials.TLSInfo:
		if info == nil {
			return tls.ConnectionState{}, ErrAgentTLS
		}
		return info.State, nil
	default:
		return tls.ConnectionState{}, ErrAgentTLS
	}
}

func projectFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrAgentTLS
	}
	values := md.Get(ProjectMetadataKey)
	if len(values) != 1 || values[0] == "" {
		return "", ErrAgentTLS
	}
	return values[0], nil
}

// StreamServerInterceptor binds every gRPC bidirectional stream to the Agent
// identity authenticated by TLS, re-checks operation project scope against the
// authoritative certificate record, and cancels established streams after
// revocation/suspension/expiry.
func (a AgentTLSAuthenticator) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		state, err := tlsStateFromContext(stream.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, "agent TLS identity required")
		}
		agentPeer, err := a.authenticate(stream.Context(), state)
		if err != nil {
			return status.Error(codes.Unauthenticated, "agent certificate rejected")
		}
		projectID, err := projectFromContext(stream.Context())
		if err != nil {
			return status.Error(codes.PermissionDenied, "project scope required")
		}
		if _, err = a.AuthorizeProject(stream.Context(), state, projectID); err != nil {
			return status.Error(codes.PermissionDenied, "project scope rejected")
		}

		sessionCtx, cancel := context.WithCancel(stream.Context())
		defer cancel()

		revoked := make(chan struct{})
		var revokeOnce sync.Once
		revoke := func() {
			revokeOnce.Do(func() {
				close(revoked)
				cancel()
			})
		}
		if err = a.WatchSession(sessionCtx, agentPeer, revoke); err != nil {
			return status.Error(codes.Unauthenticated, "agent session rejected")
		}
		sessionCtx = context.WithValue(sessionCtx, agentPeerContextKey{}, agentPeer)
		wrapped := contextServerStream{ServerStream: stream, ctx: sessionCtx}

		handlerDone := make(chan error, 1)
		go func() {
			handlerDone <- handler(srv, wrapped)
		}()

		select {
		case handlerErr := <-handlerDone:
			return handlerErr
		case <-revoked:
			return status.Error(codes.Unauthenticated, "agent session revoked")
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// GRPCServerOptions returns the mandatory transport controls for the Agent
// listener. Callers should add application interceptors after these options,
// never replace the credentials or identity interceptor.
func (a AgentTLSAuthenticator) GRPCServerOptions(serverCertificate tls.Certificate) ([]grpc.ServerOption, error) {
	tlsConfig, err := a.TLSConfig(serverCertificate)
	if err != nil {
		return nil, err
	}
	if a.SessionRecheckInterval < 100*time.Millisecond || a.SessionRecheckInterval > time.Minute {
		return nil, ErrAgentTLS
	}
	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.StreamInterceptor(a.StreamServerInterceptor()),
		grpc.MaxRecvMsgSize(4 << 20),
		grpc.MaxSendMsgSize(4 << 20),
		grpc.MaxConcurrentStreams(128),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
	}, nil
}

func GRPCStatusIsAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	code := status.Code(err)
	return code == codes.Unauthenticated || code == codes.PermissionDenied || errors.Is(err, ErrAgentTLS)
}
