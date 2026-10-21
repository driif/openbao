// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

func routes() map[kmiplib.Operation]kmipserver.OperationHandler {
	return map[kmiplib.Operation]kmipserver.OperationHandler{
		kmiplib.OperationRegister:        kmipserver.HandleFunc(handleRegister),
		kmiplib.OperationCreate:          kmipserver.HandleFunc(handleCreate),
		kmiplib.OperationGet:             kmipserver.HandleFunc(handleGet),
		kmiplib.OperationGetAttributes:   kmipserver.HandleFunc(handleGetAttributes),
		kmiplib.OperationLocate:          kmipserver.HandleFunc(handleLocate),
		kmiplib.OperationActivate:        kmipserver.HandleFunc(handleActivate),
		kmiplib.OperationRevoke:          kmipserver.HandleFunc(handleRevoke),
		kmiplib.OperationDestroy:         kmipserver.HandleFunc(handleDestroy),
		kmiplib.OperationQuery:           kmipserver.HandleFunc(handleQuery),
		kmiplib.OperationEncrypt:         kmipserver.HandleFunc(handleEncrypt),
		kmiplib.OperationDecrypt:         kmipserver.HandleFunc(handleDecrypt),
		kmiplib.OperationSign:            kmipserver.HandleFunc(handleSign),
		kmiplib.OperationSignatureVerify: kmipserver.HandleFunc(handleVerify),
	}
}

// handleQuery used by the client to interrogate the server to determine its capabilities and/or protocol mechanisms.
// Per spec, Query is invocable by unauthenticated clients, so it is answered here without logging in.
func handleQuery(ctx context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	resp := &payloads.QueryResponsePayload{}

	for _, qf := range req.QueryFunction {
		switch qf {
		case kmiplib.QueryFunctionOperations:
			resp.Operations = append(resp.Operations, SupportedOperations...)
		case kmiplib.QueryFunctionObjects:
			resp.ObjectType = append(resp.ObjectType, SupportedObjectTypes...)
		case kmiplib.QueryFunctionServerInformation:
			resp.VendorIdentification = "OpenBao Transit KMIP"
		}
	}

	if len(req.QueryFunction) == 0 {
		resp.Operations = append(resp.Operations, SupportedOperations...)
		resp.ObjectType = append(resp.ObjectType, SupportedObjectTypes...)
		resp.VendorIdentification = "OpenBao Transit KMIP"
	}

	// TODO: Check if needed
	// Query Application Namespaces
	// Query Extension List
	// Query Extension Map
	// Query Attestation Types
	// Query RNGs
	// Query Validations
	// Query Profiles
	// Query Capabilities
	// Query Client Registration Methods

	return resp, nil
}

// handleRegister implements the KMIP Register operation by importing a pre-existing key into transit.
// Supported object types: SymmetricKey (raw bytes), PrivateKey (PKCS8 DER).
func handleRegister(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	if req.Object == nil || req.ObjectType == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Object and ObjectType are required for Register")
	}

	var keyBlock *kmiplib.KeyBlock
	switch req.ObjectType {
	case kmiplib.ObjectTypeSymmetricKey:
		keyBlock = &req.Object.(*kmiplib.SymmetricKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypeRaw {
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"SymmetricKey must be Raw, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	case kmiplib.ObjectTypePrivateKey:
		keyBlock = &req.Object.(*kmiplib.PrivateKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypePKCS_8 {
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"PrivateKey must be PKCS#8 DER, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	default:
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"Object type %s is not supported", ttlv.EnumStr(req.ObjectType),
		)
	}

	alg, bitlen := AlgAndBitLenFromTemplateAttribute(req.TemplateAttribute)
	if alg == 0 {
		alg = keyBlock.CryptographicAlgorithm
	}
	if bitlen == 0 {
		bitlen = keyBlock.CryptographicLength
	}

	if alg == 0 || bitlen == 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"Cryptographic Algorithm and Cryptographic Length are required",
		)
	}

	material, err := keyBlock.GetBytes()
	if err != nil {
		return nil, err
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	name := NameFromTemplateAttribute(req.TemplateAttribute)
	id, err := c.register(ctx, name, alg, bitlen, material)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: id,
	}, nil
}

// handleCreateKey implements the KMIP CreateKey operation by creating a new key in transit.
func handleCreate(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	alg, bitlen := AlgAndBitLenFromTemplateAttribute(req.TemplateAttribute)
	if alg == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Cryptographic algorithm is required")
	}
	if bitlen == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Cryptographic length is required")
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	name := NameFromTemplateAttribute(req.TemplateAttribute)
	id, err := c.create(ctx, name, alg, bitlen)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.CreateResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: id,
	}, nil
}

// handleGet implements the KMIP Get for Managed Object specified by it's Unique Identifier
func handleGet(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	obj, err := c.get(ctx, uid)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.GetResponsePayload{
		ObjectType:       obj.ObjectType(),
		UniqueIdentifier: uid,
		Object:           obj,
	}, nil
}

// handleLocate - this operation requests that the server search for one or more Managed Objects,
// depending on the attributes specified in the request.
func handleLocate(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: Storage Status Mask and Object Group Member are skipped initially
	ids, err := c.locate(ctx, req.Attribute)
	if err != nil {
		return nil, mapError(err)
	}

	// Total number of matches, reported back via Located Items
	located := int32(len(ids))

	if req.OffsetItems > 0 {
		if int(req.OffsetItems) >= len(ids) {
			ids = nil
		} else {
			ids = ids[req.OffsetItems:]
		}
	}

	if req.MaximumItems > 0 && int(req.MaximumItems) < len(ids) {
		ids = ids[:req.MaximumItems]
	}

	return &payloads.LocateResponsePayload{
		LocatedItems:     &located,
		UniqueIdentifier: ids,
	}, nil
}

// handleGetAttributes requests attributes associated with a ManagedObject. Object specified by it's Unique Identifier
// and the attributes by their name in the request.
func handleGetAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	attrs, err := c.getAttributes(ctx, uid, req.AttributeName)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attrs,
	}, nil
}

// handleActivate - This operation requests the server to activate a Managed Cryptographic Object.
func handleActivate(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.activate(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.ActivateResponsePayload{UniqueIdentifier: uid}, nil
}

// handleRevoke - This operation requests the server to revoke a Managed Cryptographic Object or an Opaque Object.
func handleRevoke(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	// TODO: Revocation Reason, Compromise Occurrence Date are skipped initially
	if err = c.revoke(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.RevokeResponsePayload{UniqueIdentifier: uid}, nil
}

// handleDestroy - This operation is used to indicate to the server that
// the key material for the specified Managed Object SHALL be destroyed.
func handleDestroy(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.destroy(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.DestroyResponsePayload{UniqueIdentifier: uid}, nil
}

// === CRYPTO OPERATIONS === //

// handleEncrypt implement single-part only
func handleEncrypt(ctx context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Encrypt is not supported",
		)
	}

	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (plaintext) is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Encrypt")
	}
	if len(req.IVCounterNonce) > 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "IVCounterNonce is not supported")
	}
	if len(req.AuthenticatedEncryptionAdditionalData) > 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"AuthenticatedEncryptionAdditionalData for Encrypt is not supported by this implementation",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	ct, err := c.encrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             ct,
	}, nil
}

// handleDecrypt support only single-part Decrypt
func handleDecrypt(ctx context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Decrypt is not supported",
		)
	}

	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (ciphertext) is required")
	}

	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Decrypt")
	}
	if len(req.IVCounterNonce) > 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "IVCounterNonce is not supported")
	}
	if len(req.AuthenticatedEncryptionAdditionalData) > 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"AuthenticatedEncryptionAdditionalData for Decrypt is not supported by this implementation",
		)
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := c.decrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             pt,
	}, nil
}

func handleSign(ctx context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Sign is not supported",
		)
	}

	// Current Implemetation supports only raw data input not DigestedData
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (input to sign) is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Sign")
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	sig, err := c.sign(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.SignResponsePayload{
		UniqueIdentifier: uid,
		SignatureData:    sig,
	}, nil
}

func handleVerify(ctx context.Context, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part SignatureVerify is not supported",
		)
	}

	// Current Implemetation supports only raw data input not DigestedData
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data is required")
	}
	if len(req.SignatureData) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "SignatureData is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for SignatureVerify")
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	valid, err := c.verify(ctx, uid, req.Data, req.SignatureData)
	if err != nil {
		return nil, mapError(err)
	}

	indicator := kmiplib.ValidityIndicatorInvalid
	if valid {
		indicator = kmiplib.ValidityIndicatorValid
	}

	return &payloads.SignatureVerifyResponsePayload{
		UniqueIdentifier:  uid,
		ValidityIndicator: indicator,
	}, nil
}
