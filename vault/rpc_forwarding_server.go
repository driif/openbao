package vault

import (
	"context"
	"errors"   // Added for errors.Is
	"net/http" // Added for http status codes in error mapping

	// "strings" // No longer directly needed here
	// "time" // No longer directly needed here
	// "encoding/json" // No longer directly needed here

	"github.com/openbao/openbao/helper/forwarding"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"

	// "github.com/openbao/openbao/sdk/v2/helper/wrapping" // No longer directly needed here
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// forwardingServer implements the gRPC ForwardingService.
type forwardingServer struct {
	forwarding.UnimplementedForwardingServiceServer
	core *Core
}

// NewForwardingServer creates a new forwarding server.
func NewForwardingServer(core *Core) *forwardingServer {
	return &forwardingServer{core: core}
}

// ForwardLogicalRequest handles a forwarded logical request from a standby node.
func (s *forwardingServer) ForwardLogicalRequest(ctx context.Context, rpcReq *forwarding.ForwardedLogicalRequest) (*forwarding.ForwardedLogicalResponse, error) {
	if s.core == nil {
		return nil, status.Errorf(codes.Internal, "core is not initialized on forwarding server")
	}

	// 1. Deserialize rpcReq into a logical.Request using the helper
	logicalReq, err := forwarding.FromRPCRequest(rpcReq)
	if err != nil {
		s.core.logger.Error("failed to deserialize forwarded request", "error", err)
		return nil, status.Errorf(codes.InvalidArgument, "failed to deserialize forwarded request: %v", err)
	}

	// 2. Context Preparation
	if s.core.activeContext == nil {
		s.core.logger.Error("core active context is nil during forwarding")
		return nil, status.Errorf(codes.Internal, "core active context is nil")
	}
	handlerCtx, cancel := context.WithCancel(s.core.activeContext)
	defer cancel()

	var nsHeaderValue string
	if rpcReq.ForwardMeta != nil {
		nsHeaderValue = rpcReq.ForwardMeta[consts.NamespaceHeaderName]
	}

	if s.core.namespaceStore == nil {
		s.core.logger.Error("namespaceStore is nil during forwarding")
		return nil, status.Errorf(codes.Internal, "namespace store not initialized")
	}
	ns, resolvedPath := s.core.namespaceStore.ResolveNamespaceFromRequest(nsHeaderValue, rpcReq.Path) // Use original path for NS resolution
	if ns == nil {
		s.core.logger.Warn("namespace not found for forwarded path", "path", rpcReq.Path, "header_ns", nsHeaderValue)
		return nil, status.Errorf(codes.NotFound, "namespace not found for path: %s", rpcReq.Path)
	}
	logicalReq.Path = resolvedPath // Update logicalReq with the path relative to the resolved namespace
	handlerCtx = namespace.ContextWithNamespace(handlerCtx, ns)

	if rpcReq.ForwardMeta != nil {
		if reqID, ok := rpcReq.ForwardMeta["request_id"]; ok && reqID != "" {
			handlerCtx = context.WithValue(handlerCtx, logical.CtxKeyInFlightRequestID{}, reqID)
		}
	}

	s.core.logger.Debug("handling forwarded request", "path", logicalReq.Path, "operation", logicalReq.Operation, "namespace", ns.Path)

	// 3. Call Core Logic
	logicalResp, err := s.core.switchedLockHandleRequest(handlerCtx, logicalReq, false) // doLocking=false

	// 4. Comprehensive Error Mapping
	if err != nil {
		s.core.logger.Error("error handling forwarded request in core", "path", logicalReq.Path, "operation", logicalReq.Operation, "error", err)
		switch {
		case errors.Is(err, consts.ErrSealed):
			return nil, status.Errorf(codes.Unavailable, "vault is sealed: %v", err)
		case errors.Is(err, consts.ErrStandby): // Should not happen if called on active
			return nil, status.Errorf(codes.FailedPrecondition, "vault is in standby: %v", err)
		case errors.Is(err, logical.ErrPermissionDenied):
			return nil, status.Errorf(codes.PermissionDenied, "permission denied: %v", err)
		case errors.Is(err, namespace.ErrNoNamespace):
			return nil, status.Errorf(codes.NotFound, "namespace error: %v", err)
		case errors.Is(err, logical.ErrInvalidRequest):
			return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
		}

		var ue errutil.UserError
		if errors.As(err, &ue) {
			return nil, status.Errorf(codes.InvalidArgument, "user error: %s", ue.Error())
		}
		var br *logical.StatusBadRequest
		if errors.As(err, &br) {
			return nil, status.Errorf(codes.InvalidArgument, "bad request: %v", err)
		}
		var se *logical.StatusError
		if errors.As(err, &se) {
			grpcCode := codes.FailedPrecondition
			switch se.StatusCode {
			case http.StatusNotFound:
				grpcCode = codes.NotFound
			case http.StatusBadRequest:
				grpcCode = codes.InvalidArgument
			case http.StatusForbidden:
				grpcCode = codes.PermissionDenied
			case http.StatusTooManyRequests:
				grpcCode = codes.ResourceExhausted
			case http.StatusServiceUnavailable:
				grpcCode = codes.Unavailable
			}
			return nil, status.Errorf(grpcCode, "status error (%d): %v", se.StatusCode, err)
		}
		return nil, status.Errorf(codes.Internal, "failed to handle request: %v", err)
	}

	if logicalResp == nil {
		s.core.logger.Error("core returned nil response and nil error for forwarded request", "path", logicalReq.Path)
		return nil, status.Errorf(codes.Internal, "core returned nil response without error")
	}

	// 5. Serialize logical.Response into rpcResp *forwarding.ForwardedLogicalResponse using the helper
	rpcResp, err := forwarding.ToRPCResponse(logicalResp)
	if err != nil {
		s.core.logger.Error("failed to serialize response for forwarding", "path", logicalReq.Path, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to serialize response for forwarding: %v", err)
	}

	return rpcResp, nil
}
