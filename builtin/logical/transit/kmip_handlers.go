// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"strconv"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// callTransit constructs an internal logical.Request and routes it through the transit backend.
// It returns the response or an error. If the response contains an error, the error is returned.
func callTransit(ctx context.Context, b *backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.IsError() {
		return nil, fmt.Errorf("transit error: %s", resp.Error())
	}
	return resp, nil
}

// kmipAlgorithmToTransitType maps a KMIP CryptographicAlgorithm and bit length to a transit key type string.
func kmipAlgorithmToTransitType(alg kmip.CryptographicAlgorithm, bitLen int32) (string, error) {
	switch alg {
	case kmip.CryptographicAlgorithmAES:
		switch bitLen {
		case 128:
			return "aes128-gcm96", nil
		case 256, 0:
			return "aes256-gcm96", nil
		default:
			return "", fmt.Errorf("unsupported AES key size %d bits", bitLen)
		}
	case kmip.CryptographicAlgorithmRSA:
		switch bitLen {
		case 2048:
			return "rsa-2048", nil
		case 3072:
			return "rsa-3072", nil
		case 4096, 0:
			return "rsa-4096", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size %d bits", bitLen)
		}
	case kmip.CryptographicAlgorithmECDSA, kmip.CryptographicAlgorithmEC:
		switch bitLen {
		case 256, 0:
			return "ecdsa-p256", nil
		case 384:
			return "ecdsa-p384", nil
		case 521:
			return "ecdsa-p521", nil
		default:
			return "", fmt.Errorf("unsupported EC key size %d bits", bitLen)
		}
	case kmip.CryptographicAlgorithmChaCha20Poly1305:
		return "chacha20-poly1305", nil
	default:
		return "", fmt.Errorf("unsupported KMIP algorithm: %s", ttlv.EnumStr(alg))
	}
}

// transitTypeToKmipAlgorithm maps a transit KeyType to a KMIP CryptographicAlgorithm and bit length.
func transitTypeToKmipAlgorithm(t keysutil.KeyType) (kmip.CryptographicAlgorithm, int32) {
	switch t {
	case keysutil.KeyType_AES128_GCM96:
		return kmip.CryptographicAlgorithmAES, 128
	case keysutil.KeyType_AES256_GCM96:
		return kmip.CryptographicAlgorithmAES, 256
	case keysutil.KeyType_ChaCha20_Poly1305, keysutil.KeyType_XChaCha20_Poly1305:
		return kmip.CryptographicAlgorithmChaCha20Poly1305, 256
	case keysutil.KeyType_RSA2048:
		return kmip.CryptographicAlgorithmRSA, 2048
	case keysutil.KeyType_RSA3072:
		return kmip.CryptographicAlgorithmRSA, 3072
	case keysutil.KeyType_RSA4096:
		return kmip.CryptographicAlgorithmRSA, 4096
	case keysutil.KeyType_ECDSA_P256:
		return kmip.CryptographicAlgorithmECDSA, 256
	case keysutil.KeyType_ECDSA_P384:
		return kmip.CryptographicAlgorithmECDSA, 384
	case keysutil.KeyType_ECDSA_P521:
		return kmip.CryptographicAlgorithmECDSA, 521
	case keysutil.KeyType_HMAC:
		return kmip.CryptographicAlgorithmHMACSHA256, 0
	default:
		return 0, 0
	}
}

// getKmipNameFromTemplateAttribute extracts the key name from a TemplateAttribute.
// Falls back to a randomly generated UUID if no name is set.
func getKmipNameFromTemplateAttribute(ta kmip.TemplateAttribute) (string, error) {
	for _, attr := range ta.Attribute {
		if attr.AttributeName == kmip.AttributeNameName {
			if n, ok := attr.AttributeValue.(kmip.Name); ok && n.NameValue != "" {
				return n.NameValue, nil
			}
		}
	}
	// Generate a UUID as the key name when none is provided
	b := make([]byte, 16)
	if _, err := io.ReadFull(cryptoRand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate key name: %w", err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// getKmipAttributeAlgorithmAndLength extracts CryptographicAlgorithm and CryptographicLength
// from a TemplateAttribute's attribute list.
func getKmipAttributeAlgorithmAndLength(ta kmip.TemplateAttribute) (kmip.CryptographicAlgorithm, int32) {
	var alg kmip.CryptographicAlgorithm
	var length int32
	for _, attr := range ta.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameCryptographicAlgorithm:
			if v, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm); ok {
				alg = v
			}
		case kmip.AttributeNameCryptographicLength:
			if v, ok := attr.AttributeValue.(int32); ok {
				length = v
			}
		}
	}
	return alg, length
}

// registerKmipHandlers registers all KMIP key management operation handlers with the executor.
// It is called from newTransitKmipServer after the auth middleware is registered.
func registerKmipHandlers(executor *kmipserver.BatchExecutor, b *backend) {
	executor.Route(kmip.OperationCreate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
		return handleCreate(ctx, b, req)
	}))
	executor.Route(kmip.OperationGet, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
		return handleGet(ctx, b, req)
	}))
	executor.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
		return handleGetAttributes(ctx, b, req)
	}))
	executor.Route(kmip.OperationLocate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
		return handleLocate(ctx, b, req)
	}))
	executor.Route(kmip.OperationDestroy, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
		return handleDestroy(ctx, b, req)
	}))
	executor.Route(kmip.OperationActivate, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return handleActivate(ctx, b, req)
	}))
	executor.Route(kmip.OperationRevoke, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
		return handleRevoke(ctx, b, req)
	}))
	executor.Route(kmip.OperationRegister, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
		return handleRegister(ctx, b, req)
	}))
}

// handleCreate implements the KMIP Create operation by creating a new transit key.
// The key name is taken from the Name attribute in TemplateAttribute, or a UUID is generated.
// The key type is derived from CryptographicAlgorithm + CryptographicLength attributes.
func handleCreate(ctx context.Context, b *backend, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	alg, bitLen := getKmipAttributeAlgorithmAndLength(req.TemplateAttribute)
	if alg == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "CryptographicAlgorithm is required")
	}

	keyType, err := kmipAlgorithmToTransitType(alg, bitLen)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "%s", err.Error())
	}

	name, err := getKmipNameFromTemplateAttribute(req.TemplateAttribute)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to determine key name: %s", err)
	}

	if err := authorizeOperation(ctx, kmip.OperationCreate, name); err != nil {
		return nil, err
	}

	_, err = callTransit(ctx, b, storage, logical.UpdateOperation, "keys/"+name, map[string]interface{}{
		"type":       keyType,
		"exportable": true,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to create key: %s", err)
	}

	return &payloads.CreateResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: name,
	}, nil
}

// handleGet implements the KMIP Get operation by returning raw key material from a transit key.
// The key must have exportable=true; otherwise PermissionDenied is returned.
func handleGet(ctx context.Context, b *backend, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if name == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "UniqueIdentifier is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationGet, name); err != nil {
		return nil, err
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to read key: %s", err)
	}
	if p == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key %q not found", name)
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if !p.Exportable {
		return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "key %q is not exportable", name)
	}
	if p.SoftDeleted {
		return nil, kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key %q is soft deleted", name)
	}

	versionStr := strconv.Itoa(p.LatestVersion)
	keyEntry, ok := p.Keys[versionStr]
	if !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "key version %s not found", versionStr)
	}

	switch p.Type {
	case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96:
		alg := kmip.CryptographicAlgorithmAES
		bitLen := int32(len(keyEntry.Key) * 8)
		keyBytes := make([]byte, len(keyEntry.Key))
		copy(keyBytes, keyEntry.Key)
		symKey := &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: alg,
				CryptographicLength:    bitLen,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							Bytes: &keyBytes,
						},
					},
				},
			},
		}
		return &payloads.GetResponsePayload{
			ObjectType:       kmip.ObjectTypeSymmetricKey,
			UniqueIdentifier: name,
			Object:           symKey,
		}, nil

	case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
		if keyEntry.RSAKey == nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "RSA key material not available")
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(keyEntry.RSAKey)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to marshal RSA key: %s", err)
		}
		privKey := &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypePKCS_8,
				CryptographicAlgorithm: kmip.CryptographicAlgorithmRSA,
				CryptographicLength:    int32(keyEntry.RSAKey.N.BitLen()),
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							Bytes: &pkcs8,
						},
					},
				},
			},
		}
		return &payloads.GetResponsePayload{
			ObjectType:       kmip.ObjectTypePrivateKey,
			UniqueIdentifier: name,
			Object:           privKey,
		}, nil

	case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
		if keyEntry.EC_D == nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "EC key material not available")
		}
		var curve elliptic.Curve
		switch p.Type {
		case keysutil.KeyType_ECDSA_P256:
			curve = elliptic.P256()
		case keysutil.KeyType_ECDSA_P384:
			curve = elliptic.P384()
		case keysutil.KeyType_ECDSA_P521:
			curve = elliptic.P521()
		}
		ecKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     keyEntry.EC_X,
				Y:     keyEntry.EC_Y,
			},
			D: keyEntry.EC_D,
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to marshal EC key: %s", err)
		}
		privKey := &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypePKCS_8,
				CryptographicAlgorithm: kmip.CryptographicAlgorithmECDSA,
				CryptographicLength:    int32(curve.Params().BitSize),
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{
							Bytes: &pkcs8,
						},
					},
				},
			},
		}
		return &payloads.GetResponsePayload{
			ObjectType:       kmip.ObjectTypePrivateKey,
			UniqueIdentifier: name,
			Object:           privKey,
		}, nil

	default:
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "Get not supported for key type %s", p.Type)
	}
}

// handleGetAttributes implements the KMIP GetAttributes operation by reading key metadata.
func handleGetAttributes(ctx context.Context, b *backend, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if name == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "UniqueIdentifier is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationGetAttributes, name); err != nil {
		return nil, err
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to read key: %s", err)
	}
	if p == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key %q not found", name)
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if p.SoftDeleted {
		return nil, kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key %q is soft deleted", name)
	}

	alg, bitLen := transitTypeToKmipAlgorithm(p.Type)
	state := kmip.StateActive

	attrs := []kmip.Attribute{
		{AttributeName: kmip.AttributeNameUniqueIdentifier, AttributeValue: name},
		{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSymmetricKey},
		{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: alg},
		{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: bitLen},
		{AttributeName: kmip.AttributeNameState, AttributeValue: state},
	}

	versionStr := strconv.Itoa(p.LatestVersion)
	if keyEntry, ok := p.Keys[versionStr]; ok {
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameInitialDate,
			AttributeValue: keyEntry.CreationTime,
		})
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameActivationDate,
			AttributeValue: keyEntry.CreationTime,
		})
	}

	// Filter to only requested attributes if specific names were given
	if len(req.AttributeName) > 0 {
		filtered := make([]kmip.Attribute, 0, len(req.AttributeName))
		for _, reqName := range req.AttributeName {
			for _, a := range attrs {
				if a.AttributeName == reqName {
					filtered = append(filtered, a)
					break
				}
			}
		}
		attrs = filtered
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: name,
		Attribute:        attrs,
	}, nil
}

// handleLocate implements the KMIP Locate operation by listing all transit keys.
func handleLocate(ctx context.Context, b *backend, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	if err := authorizeOperation(ctx, kmip.OperationLocate, ""); err != nil {
		return nil, err
	}

	keys, err := storage.List(ctx, "policy/")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to list keys: %s", err)
	}

	// Apply offset if specified
	offset := int(req.OffsetItems)
	if offset > len(keys) {
		offset = len(keys)
	}
	ids := keys[offset:]

	// Apply MaximumItems limit if specified
	if req.MaximumItems > 0 && int(req.MaximumItems) < len(ids) {
		ids = ids[:req.MaximumItems]
	}

	total := int32(len(keys))
	return &payloads.LocateResponsePayload{
		UniqueIdentifier: ids,
		LocatedItems:     &total,
	}, nil
}

// handleDestroy implements the KMIP Destroy operation by permanently deleting a transit key.
// It first enables deletion on the key (setting deletion_allowed=true) then deletes it.
func handleDestroy(ctx context.Context, b *backend, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if name == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "UniqueIdentifier is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationDestroy, name); err != nil {
		return nil, err
	}

	// Enable deletion on the key first
	_, err := callTransit(ctx, b, storage, logical.UpdateOperation, "keys/"+name+"/config", map[string]interface{}{
		"deletion_allowed": true,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to enable deletion for key %q: %s", name, err)
	}

	// Now permanently delete the key
	_, err = callTransit(ctx, b, storage, logical.DeleteOperation, "keys/"+name, nil)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to destroy key %q: %s", name, err)
	}

	return &payloads.DestroyResponsePayload{
		UniqueIdentifier: name,
	}, nil
}

// handleActivate implements the KMIP Activate operation.
// Transit keys are always in the Active state, so this is a no-op that returns success.
func handleActivate(ctx context.Context, b *backend, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	name := req.UniqueIdentifier
	if name == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "UniqueIdentifier is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationActivate, name); err != nil {
		return nil, err
	}

	return &payloads.ActivateResponsePayload{
		UniqueIdentifier: name,
	}, nil
}

// handleRevoke implements the KMIP Revoke operation by soft-deleting the transit key.
// A soft-deleted key cannot be used for cryptographic operations but its metadata is preserved.
func handleRevoke(ctx context.Context, b *backend, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if name == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "UniqueIdentifier is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationRevoke, name); err != nil {
		return nil, err
	}

	_, err := callTransit(ctx, b, storage, logical.DeleteOperation, "keys/"+name+"/soft-delete", nil)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to revoke key %q: %s", name, err)
	}

	return &payloads.RevokeResponsePayload{
		UniqueIdentifier: name,
	}, nil
}

// handleRegister implements the KMIP Register operation by importing a pre-existing key into transit.
// Supported object types: SymmetricKey (raw bytes), PrivateKey (PKCS8 DER).
func handleRegister(ctx context.Context, b *backend, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name, err := getKmipNameFromTemplateAttribute(req.TemplateAttribute)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to determine key name: %s", err)
	}

	if err := authorizeOperation(ctx, kmip.OperationRegister, name); err != nil {
		return nil, err
	}

	alg, bitLen := getKmipAttributeAlgorithmAndLength(req.TemplateAttribute)
	if alg == 0 {
		// Infer algorithm from object type
		switch req.ObjectType {
		case kmip.ObjectTypeSymmetricKey:
			alg = kmip.CryptographicAlgorithmAES
		default:
			return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "CryptographicAlgorithm is required for Register")
		}
	}

	keyType, err := kmipAlgorithmToTransitType(alg, bitLen)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "%s", err.Error())
	}

	// Extract raw key bytes from the KMIP object
	var keyBytes []byte
	var isPrivateKey bool

	switch obj := req.Object.(type) {
	case *kmip.SymmetricKey:
		keyBytes, err = obj.KeyMaterial()
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "failed to extract symmetric key material: %s", err)
		}
		isPrivateKey = false
	case *kmip.PrivateKey:
		raw, err := obj.KeyBlock.GetBytes()
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "failed to extract private key material: %s", err)
		}
		keyBytes = raw
		isPrivateKey = true
	default:
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "unsupported object type for Register: %T", req.Object)
	}

	// Map transit key type string to keysutil.KeyType
	var ktype keysutil.KeyType
	switch keyType {
	case "aes128-gcm96":
		ktype = keysutil.KeyType_AES128_GCM96
	case "aes256-gcm96":
		ktype = keysutil.KeyType_AES256_GCM96
	case "chacha20-poly1305":
		ktype = keysutil.KeyType_ChaCha20_Poly1305
	case "rsa-2048":
		ktype = keysutil.KeyType_RSA2048
	case "rsa-3072":
		ktype = keysutil.KeyType_RSA3072
	case "rsa-4096":
		ktype = keysutil.KeyType_RSA4096
	case "ecdsa-p256":
		ktype = keysutil.KeyType_ECDSA_P256
	case "ecdsa-p384":
		ktype = keysutil.KeyType_ECDSA_P384
	case "ecdsa-p521":
		ktype = keysutil.KeyType_ECDSA_P521
	default:
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "unsupported key type for import: %s", keyType)
	}

	polReq := keysutil.PolicyRequest{
		Storage:      storage,
		Name:         name,
		KeyType:      ktype,
		Exportable:   true,
		IsPrivateKey: isPrivateKey,
	}

	if err := b.lm.ImportPolicy(ctx, polReq, keyBytes, b.GetRandomReader()); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to import key: %s", err)
	}

	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: name,
	}, nil
}
