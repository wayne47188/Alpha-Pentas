package transport

import (
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const AgentControlConnectMethod = "/alpha.v1.AgentControl/Connect"

type AgentControlServer interface {
	Connect(grpc.ServerStream) error
}

type BootstrapAgentControl struct{}

func (BootstrapAgentControl) Connect(stream grpc.ServerStream) error {
	if _, ok := AgentPeerFromContext(stream.Context()); !ok {
		return status.Error(codes.Unauthenticated, "agent identity missing")
	}
	for {
		var message emptypb.Empty
		if err := stream.RecvMsg(&message); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
			return err
		}
	}
}

func RegisterAgentControlServer(registrar grpc.ServiceRegistrar, service AgentControlServer) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: "alpha.v1.AgentControl",
		HandlerType: (*AgentControlServer)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Connect",
			ServerStreams: true,
			ClientStreams: true,
			Handler: func(srv any, stream grpc.ServerStream) error {
				return srv.(AgentControlServer).Connect(stream)
			},
		}},
	}, service)
}
