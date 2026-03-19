// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

// authCtx returns a context pre-loaded with an allow-all kmipRole.
func authCtx() context.Context {
	role := &kmipRole{
		CertSubjectDN:     "CN=test",
		AllowedOperations: nil, // nil = allow all
		AllowedKeyNames:   nil, // nil = allow all keys
	}
	return context.WithValue(context.Background(), ctxKmipRole{}, role)
}

// setupHandlerBackend creates a backend and sets b.storage, returning both.
func setupHandlerBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, storage := createBackendWithSysView(t)
	b.storage = storage
	return b, storage
}

// createKeyViaTransit creates a transit key using the normal callTransit helper.
func createKeyViaTransit(t *testing.T, b *backend, storage logical.Storage, name, keyType string) {
	t.Helper()
	_, err := callTransit(context.Background(), b, storage, logical.UpdateOperation, "keys/"+name, map[string]interface{}{
		"type":       keyType,
		"exportable": true,
	})
	require.NoError(t, err)
}

// --- callTransit tests ---

func TestCallTransit_ListKeys(t *testing.T) {
	b, storage := setupHandlerBackend(t)

	// No keys yet
	resp, err := callTransit(context.Background(), b, storage, logical.ListOperation, "keys/", nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Create a key
	createKeyViaTransit(t, b, storage, "mykey", "aes256-gcm96")

	// List should now contain the key
	resp, err = callTransit(context.Background(), b, storage, logical.ListOperation, "keys/", nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	require.Contains(t, keys, "mykey")
}

func TestCallTransit_ErrorResponse(t *testing.T) {
	b, storage := setupHandlerBackend(t)

	// Attempt to delete a key without allowing deletion should return an error response
	createKeyViaTransit(t, b, storage, "testkey", "aes256-gcm96")
	_, err := callTransit(context.Background(), b, storage, logical.DeleteOperation, "keys/testkey", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "deletion")
}

// --- kmipAlgorithmToTransitType tests ---

func TestKmipAlgorithmToTransitType(t *testing.T) {
	tests := []struct {
		alg      kmip.CryptographicAlgorithm
		bitLen   int32
		expected string
		wantErr  bool
	}{
		{kmip.CryptographicAlgorithmAES, 128, "aes128-gcm96", false},
		{kmip.CryptographicAlgorithmAES, 256, "aes256-gcm96", false},
		{kmip.CryptographicAlgorithmAES, 0, "aes256-gcm96", false},
		{kmip.CryptographicAlgorithmAES, 512, "", true},
		{kmip.CryptographicAlgorithmRSA, 2048, "rsa-2048", false},
		{kmip.CryptographicAlgorithmRSA, 3072, "rsa-3072", false},
		{kmip.CryptographicAlgorithmRSA, 4096, "rsa-4096", false},
		{kmip.CryptographicAlgorithmRSA, 0, "rsa-4096", false},
		{kmip.CryptographicAlgorithmECDSA, 256, "ecdsa-p256", false},
		{kmip.CryptographicAlgorithmECDSA, 384, "ecdsa-p384", false},
		{kmip.CryptographicAlgorithmECDSA, 521, "ecdsa-p521", false},
		{kmip.CryptographicAlgorithmEC, 0, "ecdsa-p256", false},
		{kmip.CryptographicAlgorithmChaCha20Poly1305, 0, "chacha20-poly1305", false},
	}

	for _, tc := range tests {
		result, err := kmipAlgorithmToTransitType(tc.alg, tc.bitLen)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		}
	}
}

// --- handleCreate tests ---

func TestHandleCreate_AES256(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "test-aes-key"}},
			},
		},
	}

	resp, err := handleCreate(ctx, b, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "test-aes-key", resp.UniqueIdentifier)
	require.Equal(t, kmip.ObjectTypeSymmetricKey, resp.ObjectType)
}

func TestHandleCreate_AES128(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(128)},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "test-aes128-key"}},
			},
		},
	}

	resp, err := handleCreate(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "test-aes128-key", resp.UniqueIdentifier)
}

func TestHandleCreate_GeneratesNameWhenMissing(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
			},
		},
	}

	resp, err := handleCreate(ctx, b, req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.UniqueIdentifier)
}

func TestHandleCreate_MissingAlgorithm(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "noalg-key"}},
			},
		},
	}

	_, err := handleCreate(ctx, b, req)
	require.Error(t, err)
}

func TestHandleCreate_Unauthorized(t *testing.T) {
	b, _ := setupHandlerBackend(t)

	req := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "mykey"}},
			},
		},
	}

	// Context without role should be denied
	_, err := handleCreate(context.Background(), b, req)
	require.Error(t, err)
}

// --- handleGet tests ---

func TestHandleGet_AES256(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	// First create the key
	createReq := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "get-test-key"}},
			},
		},
	}
	createResp, err := handleCreate(ctx, b, createReq)
	require.NoError(t, err)

	// Get the key
	getReq := &payloads.GetRequestPayload{
		UniqueIdentifier: createResp.UniqueIdentifier,
	}
	getResp, err := handleGet(ctx, b, getReq)
	require.NoError(t, err)
	require.NotNil(t, getResp)
	require.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)
	require.Equal(t, "get-test-key", getResp.UniqueIdentifier)

	symKey, ok := getResp.Object.(*kmip.SymmetricKey)
	require.True(t, ok, "expected SymmetricKey object")
	keyBytes, err := symKey.KeyMaterial()
	require.NoError(t, err)
	require.Len(t, keyBytes, 32, "AES-256 key should be 32 bytes")
}

func TestHandleGet_KeyNotFound(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.GetRequestPayload{
		UniqueIdentifier: "nonexistent-key",
	}
	_, err := handleGet(ctx, b, req)
	require.Error(t, err)
}

func TestHandleGet_MissingUID(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.GetRequestPayload{}
	_, err := handleGet(ctx, b, req)
	require.Error(t, err)
}

// --- handleGetAttributes tests ---

func TestHandleGetAttributes_Basic(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	// Create a key
	createReq := &payloads.CreateRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "attrs-test-key"}},
			},
		},
	}
	_, err := handleCreate(ctx, b, createReq)
	require.NoError(t, err)

	attrReq := &payloads.GetAttributesRequestPayload{
		UniqueIdentifier: "attrs-test-key",
	}
	attrResp, err := handleGetAttributes(ctx, b, attrReq)
	require.NoError(t, err)
	require.NotNil(t, attrResp)
	require.Equal(t, "attrs-test-key", attrResp.UniqueIdentifier)
	require.NotEmpty(t, attrResp.Attribute)

	// Check that algorithm and length are present
	var foundAlg, foundLen bool
	for _, attr := range attrResp.Attribute {
		if attr.AttributeName == kmip.AttributeNameCryptographicAlgorithm {
			foundAlg = true
			require.Equal(t, kmip.CryptographicAlgorithmAES, attr.AttributeValue)
		}
		if attr.AttributeName == kmip.AttributeNameCryptographicLength {
			foundLen = true
			require.Equal(t, int32(256), attr.AttributeValue)
		}
	}
	require.True(t, foundAlg, "CryptographicAlgorithm attribute missing")
	require.True(t, foundLen, "CryptographicLength attribute missing")
}

func TestHandleGetAttributes_Filtered(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	createKeyViaTransit(t, b, b.storage, "filter-key", "aes256-gcm96")

	attrReq := &payloads.GetAttributesRequestPayload{
		UniqueIdentifier: "filter-key",
		AttributeName:    []kmip.AttributeName{kmip.AttributeNameCryptographicAlgorithm},
	}
	attrResp, err := handleGetAttributes(ctx, b, attrReq)
	require.NoError(t, err)
	require.Len(t, attrResp.Attribute, 1)
	require.Equal(t, kmip.AttributeNameCryptographicAlgorithm, attrResp.Attribute[0].AttributeName)
}

func TestHandleGetAttributes_NotFound(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	req := &payloads.GetAttributesRequestPayload{
		UniqueIdentifier: "missing-key",
	}
	_, err := handleGetAttributes(ctx, b, req)
	require.Error(t, err)
}

// --- handleLocate tests ---

func TestHandleLocate_Empty(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	resp, err := handleLocate(ctx, b, &payloads.LocateRequestPayload{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.UniqueIdentifier)
}

func TestHandleLocate_WithKeys(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	createKeyViaTransit(t, b, b.storage, "key-alpha", "aes256-gcm96")
	createKeyViaTransit(t, b, b.storage, "key-beta", "aes128-gcm96")

	resp, err := handleLocate(ctx, b, &payloads.LocateRequestPayload{})
	require.NoError(t, err)
	require.Contains(t, resp.UniqueIdentifier, "key-alpha")
	require.Contains(t, resp.UniqueIdentifier, "key-beta")
	require.Equal(t, int32(2), *resp.LocatedItems)
}

func TestHandleLocate_MaximumItems(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	createKeyViaTransit(t, b, b.storage, "loc-key-1", "aes256-gcm96")
	createKeyViaTransit(t, b, b.storage, "loc-key-2", "aes256-gcm96")
	createKeyViaTransit(t, b, b.storage, "loc-key-3", "aes256-gcm96")

	resp, err := handleLocate(ctx, b, &payloads.LocateRequestPayload{MaximumItems: 2})
	require.NoError(t, err)
	require.Len(t, resp.UniqueIdentifier, 2)
	require.Equal(t, int32(3), *resp.LocatedItems)
}

// --- handleDestroy tests ---

func TestHandleDestroy(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	// Create a key
	createKeyViaTransit(t, b, b.storage, "destroy-key", "aes256-gcm96")

	// Destroy it
	req := &payloads.DestroyRequestPayload{
		UniqueIdentifier: "destroy-key",
	}
	resp, err := handleDestroy(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "destroy-key", resp.UniqueIdentifier)

	// Verify key is gone (GetAttributes should fail)
	attrReq := &payloads.GetAttributesRequestPayload{UniqueIdentifier: "destroy-key"}
	_, err = handleGetAttributes(ctx, b, attrReq)
	require.Error(t, err)
}

func TestHandleDestroy_MissingUID(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	_, err := handleDestroy(ctx, b, &payloads.DestroyRequestPayload{})
	require.Error(t, err)
}

// --- handleActivate tests ---

func TestHandleActivate_NoOp(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	createKeyViaTransit(t, b, b.storage, "activate-key", "aes256-gcm96")

	req := &payloads.ActivateRequestPayload{UniqueIdentifier: "activate-key"}
	resp, err := handleActivate(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "activate-key", resp.UniqueIdentifier)
}

func TestHandleActivate_MissingUID(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	_, err := handleActivate(ctx, b, &payloads.ActivateRequestPayload{})
	require.Error(t, err)
}

// --- handleRevoke tests ---

func TestHandleRevoke(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	createKeyViaTransit(t, b, b.storage, "revoke-key", "aes256-gcm96")

	req := &payloads.RevokeRequestPayload{
		UniqueIdentifier: "revoke-key",
		RevocationReason: kmip.RevocationReason{
			RevocationReasonCode: kmip.RevocationReasonCodeCessationOfOperation,
		},
	}
	resp, err := handleRevoke(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "revoke-key", resp.UniqueIdentifier)

	// After soft-delete, GetAttributes should fail (soft-deleted key)
	attrReq := &payloads.GetAttributesRequestPayload{UniqueIdentifier: "revoke-key"}
	_, err = handleGetAttributes(ctx, b, attrReq)
	require.Error(t, err)
}

func TestHandleRevoke_MissingUID(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	_, err := handleRevoke(ctx, b, &payloads.RevokeRequestPayload{})
	require.Error(t, err)
}

// --- handleRegister tests ---

func TestHandleRegister_SymmetricKey(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	// Create a raw 32-byte AES key to register
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}

	symKey := &kmip.SymmetricKey{
		KeyBlock: kmip.KeyBlock{
			KeyFormatType:          kmip.KeyFormatTypeRaw,
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			CryptographicLength:    256,
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: kmip.KeyMaterial{
						Bytes: &rawKey,
					},
				},
			},
		},
	}

	req := &payloads.RegisterRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmip.CryptographicAlgorithmAES},
				{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: int32(256)},
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "imported-aes-key"}},
			},
		},
		Object: symKey,
	}

	resp, err := handleRegister(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "imported-aes-key", resp.UniqueIdentifier)

	// Verify the key exists by getting its attributes
	attrResp, err := handleGetAttributes(ctx, b, &payloads.GetAttributesRequestPayload{
		UniqueIdentifier: "imported-aes-key",
	})
	require.NoError(t, err)
	require.Equal(t, "imported-aes-key", attrResp.UniqueIdentifier)
}

func TestHandleRegister_MissingAlgorithm(t *testing.T) {
	b, _ := setupHandlerBackend(t)
	ctx := authCtx()

	rawKey := make([]byte, 32)
	symKey := &kmip.SymmetricKey{
		KeyBlock: kmip.KeyBlock{
			KeyFormatType: kmip.KeyFormatTypeRaw,
			KeyValue: &kmip.KeyValue{
				Plain: &kmip.PlainKeyValue{
					KeyMaterial: kmip.KeyMaterial{
						Bytes: &rawKey,
					},
				},
			},
		},
	}

	// No algorithm specified AND ObjectType is SymmetricKey, so it should infer AES
	req := &payloads.RegisterRequestPayload{
		ObjectType: kmip.ObjectTypeSymmetricKey,
		TemplateAttribute: kmip.TemplateAttribute{
			Attribute: []kmip.Attribute{
				{AttributeName: kmip.AttributeNameName, AttributeValue: kmip.Name{NameValue: "infer-alg-key"}},
			},
		},
		Object: symKey,
	}

	// Without explicit length, bitLen=0 maps to aes256-gcm96, requiring 32-byte key
	resp, err := handleRegister(ctx, b, req)
	require.NoError(t, err)
	require.Equal(t, "infer-alg-key", resp.UniqueIdentifier)
}

// --- transitTypeToKmipAlgorithm tests ---

func TestTransitTypeToKmipAlgorithm(t *testing.T) {
	tests := []struct {
		ktype   keysutil.KeyType
		expAlg  kmip.CryptographicAlgorithm
		expBits int32
	}{
		{keysutil.KeyType_AES128_GCM96, kmip.CryptographicAlgorithmAES, 128},
		{keysutil.KeyType_AES256_GCM96, kmip.CryptographicAlgorithmAES, 256},
		{keysutil.KeyType_RSA2048, kmip.CryptographicAlgorithmRSA, 2048},
		{keysutil.KeyType_RSA4096, kmip.CryptographicAlgorithmRSA, 4096},
		{keysutil.KeyType_ECDSA_P256, kmip.CryptographicAlgorithmECDSA, 256},
		{keysutil.KeyType_ECDSA_P384, kmip.CryptographicAlgorithmECDSA, 384},
	}

	for _, tc := range tests {
		alg, bits := transitTypeToKmipAlgorithm(tc.ktype)
		require.Equal(t, tc.expAlg, alg)
		require.Equal(t, tc.expBits, bits)
	}
}
