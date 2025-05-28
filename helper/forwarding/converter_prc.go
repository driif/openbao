package forwarding

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToRPCRequest converts logical.Request to ForwardedLogicalRequest.
func ToRPCRequest(logicalReq *logical.Request, forwardMeta map[string]string) (*ForwardedLogicalRequest, error) {
	if logicalReq == nil {
		return nil, fmt.Errorf("nil logical.Request provided to ToRPCRequest")
	}

	rpcRequest := &ForwardedLogicalRequest{
		Path:            logicalReq.Path,
		Operation:       string(logicalReq.Operation),
		ClientToken:     logicalReq.ClientToken,
		EntityId:        logicalReq.EntityID,
		DisplayName:     logicalReq.DisplayName,
		Unauthenticated: logicalReq.Unauthenticated,
		ForwardMeta:     forwardMeta,
	}

	if logicalReq.Data != nil {
		structData, err := structpb.NewStruct(logicalReq.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to convert request data to protobuf Struct: %w", err)
		}
		rpcRequest.Data = structData
	}

	if logicalReq.Headers != nil {
		rpcRequest.Headers = &ForwardedHeader{Header: make(map[string]*StringArray, len(logicalReq.Headers))}
		for k, v := range logicalReq.Headers {
			rpcRequest.Headers.Header[k] = &StringArray{Values: v}
		}
	}

	if logicalReq.Connection != nil {
		rpcRequest.Connection = &ForwardedConnectionInfo{RemoteAddr: logicalReq.Connection.RemoteAddr}
	}

	if logicalReq.WrapInfo != nil {
		serializedWrapInfo, err := json.Marshal(logicalReq.WrapInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request wrap_info: %w", err)
		}
		rpcRequest.WrapInfo = &ForwardedRequestWrapper{SerializedWrapperInfo: serializedWrapInfo}
	}

	if logicalReq.MFACreds != nil {
		serializedMFACreds, err := json.Marshal(logicalReq.MFACreds)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request mfa_creds: %w", err)
		}
		rpcRequest.MfaCreds = serializedMFACreds
	}

	return rpcRequest, nil
}

// FromRPCRequest converts ForwardedLogicalRequest to logical.Request.
func FromRPCRequest(rpcReq *ForwardedLogicalRequest) (*logical.Request, error) {
	if rpcReq == nil {
		return nil, fmt.Errorf("nil ForwardedLogicalRequest provided to FromRPCRequest")
	}

	logicalReq := &logical.Request{
		Path:            rpcReq.Path,
		ClientToken:     rpcReq.ClientToken,
		EntityID:        rpcReq.EntityId,
		DisplayName:     rpcReq.DisplayName,
		Unauthenticated: rpcReq.Unauthenticated,
	}

	op := logical.Operation(strings.ToLower(rpcReq.Operation))
	switch op {
	case logical.ReadOperation, logical.DeleteOperation, logical.ListOperation,
		logical.HelpOperation, logical.CreateOperation, logical.UpdateOperation, logical.PatchOperation,
		logical.RevokeOperation, logical.RenewOperation:
		logicalReq.Operation = op
	default:
		if rpcReq.Operation == "" {
			return nil, fmt.Errorf("empty operation string provided")
		}
		return nil, fmt.Errorf("invalid operation string: %s", rpcReq.Operation)
	}

	if rpcReq.Data != nil {
		logicalReq.Data = rpcReq.Data.AsMap()
	}

	if rpcReq.Headers != nil && rpcReq.Headers.Header != nil {
		logicalReq.Headers = make(map[string][]string, len(rpcReq.Headers.Header))
		for k, v := range rpcReq.Headers.Header {
			if v != nil {
				logicalReq.Headers[k] = v.Values
			}
		}
	}

	if rpcReq.Connection != nil {
		logicalReq.Connection = &logical.Connection{
			RemoteAddr: rpcReq.Connection.RemoteAddr,
		}
	}

	return logicalReq, nil
}

// ToRPCResponse converts logical.Response to ForwardedLogicalResponse.
func ToRPCResponse(logicalResp *logical.Response) (*ForwardedLogicalResponse, error) {
	if logicalResp == nil {
		return &ForwardedLogicalResponse{}, nil
	}

	rpcResp := &ForwardedLogicalResponse{
		Redirect: logicalResp.Redirect,
		Warnings: logicalResp.Warnings,
	}

	if logicalResp.Data != nil && len(logicalResp.Data) > 0 {
		structData, err := structpb.NewStruct(logicalResp.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to convert response data to protobuf Struct: %w", err)
		}
		rpcResp.Data = structData
	}

	if logicalResp.Secret != nil {
		rpcResp.Secret = &ForwardedSecret{
			Ttl:       int64(logicalResp.Secret.TTL.Seconds()),
			LeaseId:   logicalResp.Secret.LeaseID,
			Renewable: logicalResp.Secret.Renewable,
		}
		if logicalResp.Secret.InternalData != nil && len(logicalResp.Secret.InternalData) > 0 {
			structData, err := structpb.NewStruct(logicalResp.Secret.InternalData)
			if err != nil {
				return nil, fmt.Errorf("failed to convert secret InternalData to protobuf Struct: %w", err)
			}
			rpcResp.Secret.Data = structData
		}
	}

	if logicalResp.Auth != nil {
		// Convert TokenType enum to string - assuming String() returns valid token type string
		tokenTypeStr := logicalResp.Auth.TokenType.String()
		rpcResp.Auth = &ForwardedAuth{
			ClientToken:               logicalResp.Auth.ClientToken,
			Accessor:                  logicalResp.Auth.Accessor,
			DisplayName:               logicalResp.Auth.DisplayName,
			Policies:                  logicalResp.Auth.Policies,
			Metadata:                  logicalResp.Auth.Metadata,
			LeaseDuration:             int64(logicalResp.Auth.TTL.Seconds()),
			Renewable:                 logicalResp.Auth.Renewable,
			EntityId:                  logicalResp.Auth.EntityID,
			TokenType:                 tokenTypeStr,
			NumUses:                   int64(logicalResp.Auth.NumUses),
			ExplicitMaxTtl:            int64(logicalResp.Auth.ExplicitMaxTTL.Seconds()),
			Period:                    int64(logicalResp.Auth.Period.Seconds()),
			IdentityPolicies:          logicalResp.Auth.IdentityPolicies,
			ExternalNamespacePolicies: make(map[string]*StringArray, len(logicalResp.Auth.ExternalNamespacePolicies)),
		}
		for ns, policies := range logicalResp.Auth.ExternalNamespacePolicies {
			rpcResp.Auth.ExternalNamespacePolicies[ns] = &StringArray{Values: policies}
		}
	}

	if logicalResp.WrapInfo != nil {
		rpcResp.WrapInfo = &ForwardedResponseWrapInfo{
			Token:           logicalResp.WrapInfo.Token,
			Ttl:             int64(logicalResp.WrapInfo.TTL.Seconds()),
			Format:          logicalResp.WrapInfo.Format,
			CreationPath:    logicalResp.WrapInfo.CreationPath,
			SealWrap:        logicalResp.WrapInfo.SealWrap,
			WrappedAccessor: logicalResp.WrapInfo.WrappedAccessor,
		}
	}

	return rpcResp, nil
}

// FromRPCResponse converts ForwardedLogicalResponse to logical.Response.
func FromRPCResponse(rpcResp *ForwardedLogicalResponse) (*logical.Response, error) {
	if rpcResp == nil {
		return nil, fmt.Errorf("nil ForwardedLogicalResponse provided to FromRPCResponse")
	}

	logicalResp := &logical.Response{
		Redirect: rpcResp.Redirect,
		Warnings: rpcResp.Warnings,
	}

	if rpcResp.Data != nil {
		logicalResp.Data = rpcResp.Data.AsMap()
	}

	if rpcResp.Secret != nil {
		logicalResp.Secret = &logical.Secret{
			LeaseID: rpcResp.Secret.LeaseId,
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Duration(rpcResp.Secret.Ttl) * time.Second,
				Renewable: rpcResp.Secret.Renewable,
			},
			InternalData: make(map[string]interface{}),
		}
		if rpcResp.Secret.Data != nil {
			logicalResp.Secret.InternalData = rpcResp.Secret.Data.AsMap()
		}
	}

	if rpcResp.Auth != nil {
		tokenTypeVal, err := logical.ParseTokenType(rpcResp.Auth.TokenType)
		if err != nil {
			return nil, fmt.Errorf("invalid token type in response: %s", rpcResp.Auth.TokenType)
		}
		logicalResp.Auth = &logical.Auth{
			ClientToken: rpcResp.Auth.ClientToken,
			Accessor:    rpcResp.Auth.Accessor,
			DisplayName: rpcResp.Auth.DisplayName,
			Policies:    rpcResp.Auth.Policies,
			Metadata:    rpcResp.Auth.Metadata,
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Duration(rpcResp.Auth.LeaseDuration) * time.Second,
				Renewable: rpcResp.Auth.Renewable,
			},
			EntityID:                  rpcResp.Auth.EntityId,
			TokenType:                 tokenTypeVal,
			NumUses:                   int(rpcResp.Auth.NumUses),
			ExplicitMaxTTL:            time.Duration(rpcResp.Auth.ExplicitMaxTtl) * time.Second,
			Period:                    time.Duration(rpcResp.Auth.Period) * time.Second,
			IdentityPolicies:          rpcResp.Auth.IdentityPolicies,
			ExternalNamespacePolicies: make(map[string][]string, len(rpcResp.Auth.ExternalNamespacePolicies)),
		}
		for ns, sa := range rpcResp.Auth.ExternalNamespacePolicies {
			if sa != nil {
				logicalResp.Auth.ExternalNamespacePolicies[ns] = sa.Values
			}
		}
	}

	if rpcResp.WrapInfo != nil {
		logicalResp.WrapInfo = &wrapping.ResponseWrapInfo{
			Token:           rpcResp.WrapInfo.Token,
			TTL:             time.Duration(rpcResp.WrapInfo.Ttl) * time.Second,
			Format:          rpcResp.WrapInfo.Format,
			CreationPath:    rpcResp.WrapInfo.CreationPath,
			SealWrap:        rpcResp.WrapInfo.SealWrap,
			WrappedAccessor: rpcResp.WrapInfo.WrappedAccessor,
		}
	}

	return logicalResp, nil
}
