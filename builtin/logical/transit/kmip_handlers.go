// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// validKmipName matches transit key names: letters, digits, hyphens, underscores.
// Slashes and dots are disallowed to prevent path traversal via UniqueIdentifier.
var validKmipName = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// validateKmipName returns an error if name is empty or contains characters that
// could be used to traverse paths (e.g. "/" or "..").
func validateKmipName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if !validKmipName.MatchString(name) {
		return fmt.Errorf("name %q contains invalid characters: only letters, digits, hyphens, and underscores are allowed", name)
	}
	return nil
}

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
	default:
		return "", fmt.Errorf("unsupported KMIP algorithm: %s", ttlv.EnumStr(alg))
	}
}

// kmipObjectTypeForKeyType returns the KMIP ObjectType for a given transit KeyType.
func kmipObjectTypeForKeyType(t keysutil.KeyType) kmip.ObjectType {
	switch t {
	case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096,
		keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
		return kmip.ObjectTypePrivateKey
	default:
		return kmip.ObjectTypeSymmetricKey
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

// registerKmipHandlers registers all KMIP key management and cryptographic operation handlers with the executor.
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
	executor.Route(kmip.OperationEncrypt, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
		return handleEncrypt(ctx, b, req)
	}))
	executor.Route(kmip.OperationDecrypt, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
		return handleDecrypt(ctx, b, req)
	}))
	executor.Route(kmip.OperationSign, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
		return handleSign(ctx, b, req)
	}))
	executor.Route(kmip.OperationSignatureVerify, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
		return handleVerify(ctx, b, req)
	}))
	executor.Route(kmip.OperationQuery, kmipserver.HandleFunc(func(ctx context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
		return handleQuery(ctx, b, req)
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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid key name: %s", err)
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

	objectType := kmip.ObjectTypeSymmetricKey
	if alg == kmip.CryptographicAlgorithmRSA || alg == kmip.CryptographicAlgorithmECDSA || alg == kmip.CryptographicAlgorithmEC {
		objectType = kmip.ObjectTypePrivateKey
	}

	return &payloads.CreateResponsePayload{
		ObjectType:       objectType,
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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
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
		{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmipObjectTypeForKeyType(p.Type)},
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

// locateMatchesAttributes returns true if the policy matches all KMIP Attribute
// filters from a Locate request. An empty filter list matches everything.
// Supported attributes: UniqueIdentifier, CryptographicAlgorithm,
// CryptographicLength, ObjectType, State.
func locateMatchesAttributes(p *keysutil.Policy, attrs []kmip.Attribute) bool {
	for _, attr := range attrs {
		switch attr.AttributeName {
		case kmip.AttributeNameUniqueIdentifier:
			v, ok := attr.AttributeValue.(string)
			if !ok || v != p.Name {
				return false
			}
		case kmip.AttributeNameCryptographicAlgorithm:
			v, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm)
			if !ok {
				return false
			}
			alg, _ := transitTypeToKmipAlgorithm(p.Type)
			if v != alg {
				return false
			}
		case kmip.AttributeNameCryptographicLength:
			v, ok := attr.AttributeValue.(int32)
			if !ok {
				return false
			}
			_, bitLen := transitTypeToKmipAlgorithm(p.Type)
			if v != bitLen {
				return false
			}
		case kmip.AttributeNameObjectType:
			v, ok := attr.AttributeValue.(kmip.ObjectType)
			if !ok {
				return false
			}
			if v != kmipObjectTypeForKeyType(p.Type) {
				return false
			}
		case kmip.AttributeNameState:
			v, ok := attr.AttributeValue.(kmip.State)
			if !ok {
				return false
			}
			// Transit keys are always Active unless soft-deleted (filtered earlier).
			if v != kmip.StateActive {
				return false
			}
		}
		// Unknown attributes are ignored — we can only match attributes we expose.
	}
	return true
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

	// Transit only stores online objects. If the request explicitly asks for
	// archived-only objects (StorageStatusMask set but StorageStatusOnlineStorage
	// bit NOT set), return an empty result rather than silently ignoring the mask.
	if req.StorageStatusMask != 0 && req.StorageStatusMask&kmip.StorageStatusOnlineStorage == 0 {
		total := int32(0)
		return &payloads.LocateResponsePayload{
			UniqueIdentifier: nil,
			LocatedItems:     &total,
		}, nil
	}

	allKeys, err := storage.List(ctx, "policy/")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to list keys: %s", err)
	}

	// Filter out soft-deleted keys — they are not usable for any KMIP operation.
	// Also apply any KMIP attribute filters from the request.
	keys := make([]string, 0, len(allKeys))
	for _, k := range allKeys {
		// Skip subdirectory entries (e.g. "archive/") returned by some storage backends.
		if strings.HasSuffix(k, "/") {
			continue
		}
		p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
			Storage: storage,
			Name:    k,
		}, b.GetRandomReader())
		if err != nil {
			b.Logger().Warn("kmip: locate skipping key due to read error", "key", k, "error", err)
			continue
		}
		if p == nil {
			continue
		}
		// When caching is disabled GetPolicy returns with the write lock held;
		// when caching is enabled we must acquire a read lock ourselves.
		if !b.System().CachingDisabled() {
			p.Lock(false)
		}
		softDeleted := p.SoftDeleted
		matchesAttrs := locateMatchesAttributes(p, req.Attribute)
		p.Unlock()
		if softDeleted || !matchesAttrs {
			continue
		}
		keys = append(keys, k)
	}

	// Filter by AllowedKeyNames if the role restricts key access.
	role := kmipRoleFromContext(ctx)
	if role != nil && len(role.AllowedKeyNames) > 0 {
		allowed := make(map[string]bool, len(role.AllowedKeyNames))
		for _, n := range role.AllowedKeyNames {
			allowed[n] = true
		}
		filtered := make([]string, 0, len(keys))
		for _, k := range keys {
			if allowed[k] {
				filtered = append(filtered, k)
			}
		}
		keys = filtered
	}

	// Apply offset if specified
	offset := int(req.OffsetItems)
	if offset < 0 {
		offset = 0
	}
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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}

	if err := authorizeOperation(ctx, kmip.OperationDestroy, name); err != nil {
		return nil, err
	}

	// Read the key's current deletion_allowed value so we can restore it if deletion fails.
	keyResp, err := callTransit(ctx, b, storage, logical.ReadOperation, "keys/"+name, nil)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to read key %q: %s", name, err)
	}
	if keyResp == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key %q not found", name)
	}
	originalDeletionAllowed, _ := keyResp.Data["deletion_allowed"].(bool)

	// Enable deletion on the key first.
	_, err = callTransit(ctx, b, storage, logical.UpdateOperation, "keys/"+name+"/config", map[string]interface{}{
		"deletion_allowed": true,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to enable deletion for key %q: %s", name, err)
	}

	// Now permanently delete the key. If deletion fails, restore deletion_allowed to its
	// original value to avoid permanently changing the key's deletion policy.
	_, err = callTransit(ctx, b, storage, logical.DeleteOperation, "keys/"+name, nil)
	if err != nil {
		if _, restoreErr := callTransit(ctx, b, storage, logical.UpdateOperation, "keys/"+name+"/config", map[string]interface{}{
			"deletion_allowed": originalDeletionAllowed,
		}); restoreErr != nil {
			b.Logger().Error("Failed to restore deletion_allowed after failed destroy", "key", name, "original", originalDeletionAllowed, "error", restoreErr)
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to destroy key %q: %s", name, err)
	}

	return &payloads.DestroyResponsePayload{
		UniqueIdentifier: name,
	}, nil
}

// handleActivate implements the KMIP Activate operation.
// Transit keys are always in the Active state, so this is a no-op that returns success.
func handleActivate(ctx context.Context, b *backend, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}

	if err := authorizeOperation(ctx, kmip.OperationActivate, name); err != nil {
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
	// Transit keys are always Active; no state change needed. Acquire and
	// immediately release the lock to match the pattern used by every other
	// handler: when caching is enabled GetPolicy returns with no lock held,
	// so we must take one before calling Unlock.
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	p.Unlock()

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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
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

// handleEncrypt implements the KMIP Encrypt operation by calling transit encrypt.
// The KMIP Data field (plaintext bytes) is base64-encoded and passed to transit.
// The transit ciphertext string is returned as the KMIP Data field.
func handleEncrypt(ctx context.Context, b *backend, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "Data (plaintext) is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationEncrypt, name); err != nil {
		return nil, err
	}

	plaintext := base64.StdEncoding.EncodeToString(req.Data)
	resp, err := callTransit(ctx, b, storage, logical.UpdateOperation, "encrypt/"+name, map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to encrypt: %s", err)
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "transit encrypt returned no ciphertext")
	}

	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: name,
		Data:             []byte(ciphertext),
	}, nil
}

// handleDecrypt implements the KMIP Decrypt operation by calling transit decrypt.
// The KMIP Data field contains the transit ciphertext string (as bytes).
// The decrypted plaintext bytes are returned as the KMIP Data field.
func handleDecrypt(ctx context.Context, b *backend, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "Data (ciphertext) is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationDecrypt, name); err != nil {
		return nil, err
	}

	resp, err := callTransit(ctx, b, storage, logical.UpdateOperation, "decrypt/"+name, map[string]interface{}{
		"ciphertext": string(req.Data),
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to decrypt: %s", err)
	}

	plaintextB64, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "transit decrypt returned no plaintext")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to decode plaintext: %s", err)
	}

	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: name,
		Data:             plaintext,
	}, nil
}

// handleSign implements the KMIP Sign operation by calling transit sign.
// The KMIP Data field (bytes to sign) is base64-encoded and passed as the transit 'input'.
// The transit signature string is returned as the KMIP SignatureData field.
func handleSign(ctx context.Context, b *backend, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "Data (input to sign) is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationSign, name); err != nil {
		return nil, err
	}

	input := base64.StdEncoding.EncodeToString(req.Data)
	resp, err := callTransit(ctx, b, storage, logical.UpdateOperation, "sign/"+name, map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to sign: %s", err)
	}

	signature, ok := resp.Data["signature"].(string)
	if !ok || signature == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "transit sign returned no signature")
	}

	return &payloads.SignResponsePayload{
		UniqueIdentifier: name,
		SignatureData:    []byte(signature),
	}, nil
}

// handleVerify implements the KMIP SignatureVerify operation by calling transit verify.
// The KMIP Data field and SignatureData are passed to transit verify.
// Returns ValidityIndicatorValid or ValidityIndicatorInvalid.
func handleVerify(ctx context.Context, b *backend, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	storage := b.storage
	if storage == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "storage not available")
	}

	name := req.UniqueIdentifier
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid UniqueIdentifier: %s", err)
	}
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "Data (original input) is required")
	}
	if len(req.SignatureData) == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "SignatureData is required")
	}

	if err := authorizeOperation(ctx, kmip.OperationSignatureVerify, name); err != nil {
		return nil, err
	}

	input := base64.StdEncoding.EncodeToString(req.Data)
	resp, err := callTransit(ctx, b, storage, logical.UpdateOperation, "verify/"+name, map[string]interface{}{
		"input":     input,
		"signature": string(req.SignatureData),
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to verify: %s", err)
	}

	valid, _ := resp.Data["valid"].(bool)
	indicator := kmip.ValidityIndicatorInvalid
	if valid {
		indicator = kmip.ValidityIndicatorValid
	}

	return &payloads.SignatureVerifyResponsePayload{
		UniqueIdentifier:  name,
		ValidityIndicator: indicator,
	}, nil
}

// handleQuery implements the KMIP Query operation by returning server capabilities.
// It reports the supported operations and object types for this transit KMIP server.
func handleQuery(ctx context.Context, _ *backend, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	if err := authorizeOperation(ctx, kmip.OperationQuery, ""); err != nil {
		return nil, err
	}

	resp := &payloads.QueryResponsePayload{}

	wantOperations := false
	wantObjects := false
	wantServerInfo := false
	for _, fn := range req.QueryFunction {
		switch fn {
		case kmip.QueryFunctionOperations:
			wantOperations = true
		case kmip.QueryFunctionObjects:
			wantObjects = true
		case kmip.QueryFunctionServerInformation:
			wantServerInfo = true
		}
	}
	// If no specific functions requested, return all info
	if len(req.QueryFunction) == 0 {
		wantOperations = true
		wantObjects = true
		wantServerInfo = true
	}

	if wantOperations {
		resp.Operations = []kmip.Operation{
			kmip.OperationCreate,
			kmip.OperationRegister,
			kmip.OperationGet,
			kmip.OperationGetAttributes,
			kmip.OperationLocate,
			kmip.OperationActivate,
			kmip.OperationRevoke,
			kmip.OperationDestroy,
			kmip.OperationEncrypt,
			kmip.OperationDecrypt,
			kmip.OperationSign,
			kmip.OperationSignatureVerify,
			kmip.OperationQuery,
		}
	}

	if wantObjects {
		resp.ObjectType = []kmip.ObjectType{
			kmip.ObjectTypeSymmetricKey,
			kmip.ObjectTypePrivateKey,
		}
	}

	if wantServerInfo {
		resp.VendorIdentification = "OpenBao Transit KMIP Server"
	}

	return resp, nil
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
	if err := validateKmipName(name); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid key name: %s", err)
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

	// Check that a key with this name does not already exist to prevent silent overwrites.
	existing, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "failed to check for existing key: %s", err)
	}
	if existing != nil {
		if !b.System().CachingDisabled() {
			existing.Lock(false)
		}
		existing.Unlock()
		return nil, kmipserver.Errorf(kmip.ResultReasonObjectAlreadyExists, "key %q already exists", name)
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
