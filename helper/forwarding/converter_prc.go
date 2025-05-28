package forwarding

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/quota"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ToRPCRequest converts a logical.Request to a ForwardedLogicalRequest.
// forwardMeta is passed directly as it's specific to the forwarding context.
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
		ForwardMeta:     forwardMeta, // Pass through directly
	}

	if logicalReq.Data != nil {
		jsonData, err := json.Marshal(logicalReq.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request data: %w", err)
		}
		rpcRequest.Data = jsonData
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

// FromRPCRequest converts a ForwardedLogicalRequest to a logical.Request.
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
	case logical.ReadOperation, logical.DeleteOperation, logical.ListOperation, logical.HelpOperation, logical.CreateOperation, logical.UpdateOperation, logical.PatchOperation, logical.RevokeOperation, logical.RenewOperation:
		logicalReq.Operation = op
	default:
		if rpcReq.Operation == "" {
			return nil, fmt.Errorf("empty operation string provided")
		}
		return nil, fmt.Errorf("invalid operation string: %s", rpcReq.Operation)
	}

	if rpcReq.Data != nil && len(rpcReq.Data) > 0 {
		if err := json.Unmarshal(rpcReq.Data, &logicalReq.Data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request data: %w", err)
		}
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

	if rpcReq.WrapInfo != nil && len(rpcReq.WrapInfo.SerializedWrapperInfo) > 0 {
		logicalReq.WrapInfo = &wrapping.RequestWrapper{}
		if err := json.Unmarshal(rpcReq.WrapInfo.SerializedWrapperInfo, logicalReq.WrapInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request wrap_info: %w", err)
		}
	}

	return logicalReq, nil
}

// ToRPCResponse converts a logical.Response to a ForwardedLogicalResponse.
func ToRPCResponse(logicalResp *logical.Response) (*ForwardedLogicalResponse, error) {
	if logicalResp == nil {
		return &ForwardedLogicalResponse{}, nil
	}

	rpcResp := &ForwardedLogicalResponse{
		Redirect: logicalResp.Redirect,
		Warnings: logicalResp.Warnings,
	}

	if logicalResp.Data != nil && len(logicalResp.Data) > 0 {
		jsonData, err := json.Marshal(logicalResp.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response data: %w", err)
		}
		rpcResp.Data = jsonData
	}

	if logicalResp.Secret != nil {
		rpcResp.Secret = &ForwardedSecret{
			Ttl:         logicalResp.Secret.TTL.Nanoseconds() / 1e9,
			LeaseId:     logicalResp.Secret.LeaseID,
			Renewable:   logicalResp.Secret.Renewable,
			DisplayName: logicalResp.Secret.DisplayName,
		}
		secretDataToMarshal := logicalResp.Secret.Data
		if secretDataToMarshal != nil && len(secretDataToMarshal) > 0 {
			jsonSecretData, err := json.Marshal(secretDataToMarshal)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal secret data: %w", err)
			}
			rpcResp.Secret.Data = jsonSecretData
		}
	}

	if logicalResp.Auth != nil {
		rpcResp.Auth = &ForwardedAuth{
			ClientToken:      logicalResp.Auth.ClientToken,
			Accessor:         logicalResp.Auth.Accessor,
			DisplayName:      logicalResp.Auth.DisplayName,
			Policies:         logicalResp.Auth.Policies,
			Metadata:         logicalResp.Auth.Metadata,
			LeaseDuration:    logicalResp.Auth.TTL.Nanoseconds() / 1e9,
			Renewable:        logicalResp.Auth.Renewable,
			EntityId:         logicalResp.Auth.EntityID,
			TokenType:        string(logicalResp.Auth.TokenType),
			NumUses:          int64(logicalResp.Auth.NumUses),
			ExplicitMaxTtl:   logicalResp.Auth.ExplicitMaxTTL.Nanoseconds() / 1e9,
			Period:           logicalResp.Auth.Period.Nanoseconds() / 1e9,
			IdentityPolicies: logicalResp.Auth.IdentityPolicies,
		}
		if logicalResp.Auth.ExternalNamespacePolicies != nil {
			rpcResp.Auth.ExternalNamespacePolicies = make(map[string]*StringArray, len(logicalResp.Auth.ExternalNamespacePolicies))
			for k, v := range logicalResp.Auth.ExternalNamespacePolicies {
				rpcResp.Auth.ExternalNamespacePolicies[k] = &StringArray{Values: v}
			}
		}
	}

	if logicalResp.WrapInfo != nil {
		rpcResp.WrapInfo = &ForwardedResponseWrapInfo{
			Token:           logicalResp.WrapInfo.Token,
			Ttl:             logicalResp.WrapInfo.TTL.Nanoseconds() / 1e9,
			Format:          logicalResp.WrapInfo.Format,
			CreationPath:    logicalResp.WrapInfo.CreationPath,
			SealWrap:        logicalResp.WrapInfo.SealWrap,
			WrappedAccessor: logicalResp.WrapInfo.WrappedAccessor,
		}
	}

	if logicalResp.MfaLoginResponse != nil {
		serializedMFA, err := json.Marshal(logicalResp.MfaLoginResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal mfa_login_response: %w", err)
		}
		rpcResp.MfaLoginResponse = serializedMFA
	}
	if logicalResp.QuotaErrorResponse != nil {
		serializedQuota, err := json.Marshal(logicalResp.QuotaErrorResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal quota_error_response: %w", err)
		}
		rpcResp.QuotaErrorResponse = serializedQuota
	}

	return rpcResp, nil
}

// FromRPCResponse converts a ForwardedLogicalResponse to a logical.Response.
func FromRPCResponse(rpcResp *ForwardedLogicalResponse) (*logical.Response, error) {
	if rpcResp == nil {
		return nil, fmt.Errorf("nil ForwardedLogicalResponse provided to FromRPCResponse")
	}

	logicalResp := &logical.Response{
		Redirect: rpcResp.Redirect,
		Warnings: rpcResp.Warnings,
	}

	if len(rpcResp.Data) > 0 {
		if err := json.Unmarshal(rpcResp.Data, &logicalResp.Data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response data: %w", err)
		}
	}

	if rpcResp.Secret != nil {
		logicalResp.Secret = &logical.Secret{
			LeaseID:     rpcResp.Secret.LeaseId,
			Renewable:   rpcResp.Secret.Renewable,
			TTL:         time.Duration(rpcResp.Secret.Ttl) * time.Second,
			DisplayName: rpcResp.Secret.DisplayName,
		}
		if len(rpcResp.Secret.Data) > 0 {
			if err := json.Unmarshal(rpcResp.Secret.Data, &logicalResp.Secret.Data); err != nil {
				return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
			}
		}
	}

	if rpcResp.Auth != nil {
		logicalResp.Auth = &logical.Auth{
			ClientToken:      rpcResp.Auth.ClientToken,
			Accessor:         rpcResp.Auth.Accessor,
			DisplayName:      rpcResp.Auth.DisplayName,
			Policies:         rpcResp.Auth.Policies,
			Metadata:         rpcResp.Auth.Metadata,
			TTL:              time.Duration(rpcResp.Auth.LeaseDuration) * time.Second,
			Renewable:        rpcResp.Auth.Renewable,
			EntityID:         rpcResp.Auth.EntityId,
			TokenType:        logical.TokenType(rpcResp.Auth.TokenType),
			NumUses:          int(rpcResp.Auth.NumUses),
			ExplicitMaxTTL:   time.Duration(rpcResp.Auth.ExplicitMaxTtl) * time.Second,
			Period:           time.Duration(rpcResp.Auth.Period) * time.Second,
			IdentityPolicies: rpcResp.Auth.IdentityPolicies,
		}
		if rpcResp.Auth.ExternalNamespacePolicies != nil {
			logicalResp.Auth.ExternalNamespacePolicies = make(map[string][]string, len(rpcResp.Auth.ExternalNamespacePolicies))
			for k, v := range rpcResp.Auth.ExternalNamespacePolicies {
				if v != nil {
					logicalResp.Auth.ExternalNamespacePolicies[k] = v.Values
				}
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

	if len(rpcResp.MfaLoginResponse) > 0 {
		logicalResp.MfaLoginResponse = &logical.MFALoginResponse{}
		if err := json.Unmarshal(rpcResp.MfaLoginResponse, logicalResp.MfaLoginResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mfa_login_response: %w", err)
		}
	}
	if len(rpcResp.QuotaErrorResponse) > 0 {
		logicalResp.QuotaErrorResponse = &quota.ErrorResponse{}
		if err := json.Unmarshal(rpcResp.QuotaErrorResponse, logicalResp.QuotaErrorResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal quota_error_response: %w", err)
		}
	}

	return logicalResp, nil
}
