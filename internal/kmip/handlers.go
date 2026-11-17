// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"maps"
	"slices"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

const vendorIdentification = "OpenBao Transit KMIP"

func routes() map[kmiplib.Operation]kmipserver.OperationHandler {
	return map[kmiplib.Operation]kmipserver.OperationHandler{
		kmiplib.OperationRegister:         handle(handleRegister),
		kmiplib.OperationCreate:           handle(handleCreate),
		kmiplib.OperationGet:              handle(handleGet),
		kmiplib.OperationGetAttributes:    handle(handleGetAttributes),
		kmiplib.OperationGetAttributeList: handle(handleGetAttributeList),
		kmiplib.OperationAddAttribute:     handle(handleAddAttribute),
		kmiplib.OperationModifyAttribute:  handle(handleModifyAttribute),
		kmiplib.OperationDeleteAttribute:  handle(handleDeleteAttribute),
		kmiplib.OperationReKey:            handle(handleRekey),
		kmiplib.OperationLocate:           handle(handleLocate),
		kmiplib.OperationActivate:         handle(handleActivate),
		kmiplib.OperationRevoke:           handle(handleRevoke),
		kmiplib.OperationDestroy:          handle(handleDestroy),
		kmiplib.OperationQuery:            handle(handleQuery),
		kmiplib.OperationEncrypt:          handle(handleEncrypt),
		kmiplib.OperationDecrypt:          handle(handleDecrypt),
		kmiplib.OperationSign:             handle(handleSign),
		kmiplib.OperationSignatureVerify:  handle(handleVerify),
	}
}

// handle routes h. An error that h did not classify reaches the client as a
// General Failure with fixed text.
func handle[Req, Resp kmiplib.OperationPayload](h func(context.Context, Req) (Resp, error)) kmipserver.OperationHandler {
	return kmipserver.HandleFunc(func(ctx context.Context, req Req) (Resp, error) {
		resp, err := h(ctx, req)
		return resp, mapError(err)
	})
}

// supportedOperations is what Query advertises: every route, and
// DiscoverVersions, which the listener's router answers itself.
func supportedOperations() []kmiplib.Operation {
	ops := append(slices.Collect(maps.Keys(routes())), kmiplib.OperationDiscoverVersions)
	slices.Sort(ops)
	return ops
}

// beginOn starts an operation on the object that reqID names, or else the
// ID Placeholder.
func beginOn(ctx context.Context, reqID string) (*call, string, error) {
	uid, err := kmipserver.GetIdOrPlaceholder(ctx, reqID)
	if err != nil {
		return nil, "", operationErrorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}
	c, err := begin(ctx)
	if err != nil {
		return nil, "", err
	}
	return c, uid, nil
}

// refuseMultiPart refuses a multi-part request.
func refuseMultiPart(op string, correlation []byte, init, final *bool) error {
	if len(correlation) > 0 || init != nil || final != nil {
		return operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "multi-part %s is not supported", op)
	}
	return nil
}

// refuseCipherOptions refuses the request fields that select a mode, a nonce
// or additional data: transit takes all three from the key type.
func refuseCipherOptions(op string, params *kmiplib.CryptographicParameters, iv, aad []byte) error {
	switch {
	case params != nil:
		return operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for %s", op)
	case len(iv) > 0:
		return operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "IVCounterNonce is not supported")
	case len(aad) > 0:
		return operationErrorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"AuthenticatedEncryptionAdditionalData for %s is not supported by this implementation", op,
		)
	}
	return nil
}

// handleQuery reports the supported operations and object types. It sends no
// request to OpenBao, so it does not log in. KMIP 1.4 requires an answer to
// Query RNGs; the remaining Query functions have nothing to report.
func handleQuery(ctx context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	functions := req.QueryFunction
	if len(functions) == 0 {
		functions = []kmiplib.QueryFunction{
			kmiplib.QueryFunctionOperations,
			kmiplib.QueryFunctionObjects,
			kmiplib.QueryFunctionServerInformation,
		}
	}

	resp := &payloads.QueryResponsePayload{}
	for _, qf := range functions {
		switch qf {
		case kmiplib.QueryFunctionOperations:
			resp.Operations = append(resp.Operations, supportedOperations()...)
		case kmiplib.QueryFunctionObjects:
			resp.ObjectType = append(resp.ObjectType,
				kmiplib.ObjectTypeSymmetricKey, kmiplib.ObjectTypePrivateKey, kmiplib.ObjectTypePublicKey)
		case kmiplib.QueryFunctionServerInformation:
			resp.VendorIdentification = vendorIdentification
		case kmiplib.QueryFunctionRNGs:
			resp.RNGParameters = []kmiplib.RNGParameters{{RNGAlgorithm: kmiplib.RNGAlgorithmUnspecified}}
		}
	}
	return resp, nil
}

// handleRegister implements the KMIP Register operation by importing a pre-existing key into transit.
// Supported object types: SymmetricKey (raw bytes), PrivateKey (PKCS8 DER).
func handleRegister(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	if req.Object == nil || req.ObjectType == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Object and ObjectType are required for Register")
	}

	var keyBlock *kmiplib.KeyBlock
	switch req.ObjectType {
	case kmiplib.ObjectTypeSymmetricKey:
		keyBlock = &req.Object.(*kmiplib.SymmetricKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypeRaw {
			return nil, operationErrorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"SymmetricKey must be Raw, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	case kmiplib.ObjectTypePrivateKey:
		keyBlock = &req.Object.(*kmiplib.PrivateKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypePKCS_8 {
			return nil, operationErrorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"PrivateKey must be PKCS#8 DER, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	default:
		return nil, operationErrorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"Object type %s is not supported", ttlv.EnumStr(req.ObjectType),
		)
	}

	alg := templateValue[kmiplib.CryptographicAlgorithm](req.TemplateAttribute, kmiplib.AttributeNameCryptographicAlgorithm)
	if alg == 0 {
		alg = keyBlock.CryptographicAlgorithm
	}
	bitlen := templateValue[int32](req.TemplateAttribute, kmiplib.AttributeNameCryptographicLength)
	if bitlen == 0 {
		bitlen = keyBlock.CryptographicLength
	}

	if alg == 0 || bitlen == 0 {
		return nil, operationErrorf(
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
	name := templateValue[kmiplib.Name](req.TemplateAttribute, kmiplib.AttributeNameName).NameValue
	id, err := c.register(ctx, name, alg, bitlen, material, &req.TemplateAttribute)
	if err != nil {
		return nil, err
	}
	kmipserver.SetIdPlaceholder(ctx, id)

	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: id,
	}, nil
}

// handleCreate implements the KMIP Create operation by creating a new key in transit.
func handleCreate(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	alg := templateValue[kmiplib.CryptographicAlgorithm](req.TemplateAttribute, kmiplib.AttributeNameCryptographicAlgorithm)
	if alg == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Cryptographic algorithm is required")
	}
	bitlen := templateValue[int32](req.TemplateAttribute, kmiplib.AttributeNameCryptographicLength)
	if bitlen == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Cryptographic length is required")
	}

	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	name := templateValue[kmiplib.Name](req.TemplateAttribute, kmiplib.AttributeNameName).NameValue
	id, err := c.create(ctx, name, alg, bitlen, &req.TemplateAttribute)
	if err != nil {
		return nil, err
	}
	kmipserver.SetIdPlaceholder(ctx, id)

	return &payloads.CreateResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: id,
	}, nil
}

// handleGet returns the object that the Unique Identifier or the ID
// Placeholder selects. The key is never wrapped or compressed, and has one
// format per object type; a request for anything else is refused.
func handleGet(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}

	if req.KeyWrappingSpecification != nil {
		return nil, operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "Key Wrapping Specification is not supported")
	}
	if req.KeyCompressionType != 0 && req.KeyCompressionType != kmiplib.KeyCompressionTypeECPublicKeyTypeUncompressed {
		return nil, operationErrorf(
			kmiplib.ResultReasonKeyCompressionTypeNotSupported,
			"Key Compression Type %s is not supported", ttlv.EnumStr(req.KeyCompressionType),
		)
	}

	obj, err := c.get(ctx, uid)
	if err != nil {
		return nil, err
	}
	if format := keyFormat(obj); req.KeyFormatType != 0 && req.KeyFormatType != format {
		return nil, operationErrorf(
			kmiplib.ResultReasonKeyFormatTypeNotSupported,
			"object %q is returned as %s, not %s", uid, ttlv.EnumStr(format), ttlv.EnumStr(req.KeyFormatType),
		)
	}

	return &payloads.GetResponsePayload{
		ObjectType:       obj.ObjectType(),
		UniqueIdentifier: uid,
		Object:           obj,
	}, nil
}

// handleLocate returns the Unique Identifiers of the objects that match the
// request's attributes. When it returns one identifier, that becomes the ID
// Placeholder; any other number returned empties it.
func handleLocate(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	c, err := begin(ctx)
	if err != nil {
		return nil, err
	}

	// No object is in archival storage, so only a search of on-line storage
	// can match. Object Group Member is ignored.
	var ids []string
	if req.StorageStatusMask == 0 || req.StorageStatusMask&kmiplib.StorageStatusOnlineStorage != 0 {
		if ids, err = c.locate(ctx, req.Attribute); err != nil {
			return nil, err
		}
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

	if len(ids) == 1 {
		kmipserver.SetIdPlaceholder(ctx, ids[0])
	} else {
		kmipserver.ClearIdPlaceholder(ctx)
	}

	return &payloads.LocateResponsePayload{
		LocatedItems:     &located,
		UniqueIdentifier: ids,
	}, nil
}

// handleGetAttributes returns the requested attributes of an object, or all
// of them when the request names none.
func handleGetAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attrs, err := c.getAttributes(ctx, uid, req.AttributeName)
	if err != nil {
		return nil, err
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attrs,
	}, nil
}

// handleGetAttributeList returns the names of every attribute the object has.
func handleGetAttributeList(ctx context.Context, req *payloads.GetAttributeListRequestPayload) (*payloads.GetAttributeListResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	names, err := c.getAttributeList(ctx, uid)
	if err != nil {
		return nil, err
	}

	return &payloads.GetAttributeListResponsePayload{
		UniqueIdentifier: uid,
		AttributeName:    names,
	}, nil
}

// handleAddAttribute adds one attribute instance to an object. The attributes
// derived from the transit key cannot be added, and Name only as the
// object's Name already.
func handleAddAttribute(ctx context.Context, req *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attr := req.Attribute
	attr.AttributeIndex = nil
	idx, err := c.addAttributeAt(ctx, uid, attr)
	if err != nil {
		return nil, err
	}
	// KMIP lets a response omit the Attribute Index only when it is 0.
	if idx > 0 {
		attr.AttributeIndex = &idx
	}

	return &payloads.AddAttributeResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attr,
	}, nil
}

// handleModifyAttribute replaces the value of one attribute instance, with
// the refusals of AddAttribute, and Name refused.
func handleModifyAttribute(ctx context.Context, req *payloads.ModifyAttributeRequestPayload) (*payloads.ModifyAttributeResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attr, err := c.modifyAttribute(ctx, uid, req.Attribute)
	if err != nil {
		return nil, err
	}

	return &payloads.ModifyAttributeResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attr,
	}, nil
}

// handleDeleteAttribute deletes one attribute instance, with the refusals of
// ModifyAttribute.
func handleDeleteAttribute(ctx context.Context, req *payloads.DeleteAttributeRequestPayload) (*payloads.DeleteAttributeResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	attr, err := c.deleteAttribute(ctx, uid, req.AttributeName, req.AttributeIndex)
	if err != nil {
		return nil, err
	}

	return &payloads.DeleteAttributeResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attr,
	}, nil
}

// handleRekey replaces a symmetric key with a new object that takes over its
// Name, and makes the replacement the ID Placeholder.
func handleRekey(ctx context.Context, req *payloads.RekeyRequestPayload) (*payloads.RekeyResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	id, err := c.rekey(ctx, uid, req.Offset, req.TemplateAttribute)
	if err != nil {
		return nil, err
	}
	kmipserver.SetIdPlaceholder(ctx, id)

	return &payloads.RekeyResponsePayload{UniqueIdentifier: id}, nil
}

// handleActivate makes a Pre-Active object Active.
func handleActivate(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err = c.activate(ctx, uid); err != nil {
		return nil, err
	}

	return &payloads.ActivateResponsePayload{UniqueIdentifier: uid}, nil
}

// handleRevoke revokes an object with the Revocation Reason of the request.
func handleRevoke(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err = c.revoke(ctx, uid, req.RevocationReason, req.CompromiseOccurrenceDate); err != nil {
		return nil, err
	}

	return &payloads.RevokeResponsePayload{UniqueIdentifier: uid}, nil
}

// handleDestroy marks an object Destroyed. It soft-deletes the transit key
// and does not purge it.
func handleDestroy(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err = c.destroy(ctx, uid); err != nil {
		return nil, err
	}

	return &payloads.DestroyResponsePayload{UniqueIdentifier: uid}, nil
}

// handleEncrypt encrypts in one part. Multi-part requests are refused.
func handleEncrypt(ctx context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := refuseMultiPart("Encrypt", req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	if len(req.Data) == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Data (plaintext) is required")
	}
	if err := refuseCipherOptions("Encrypt", req.CryptographicParameters, req.IVCounterNonce, req.AuthenticatedEncryptionAdditionalData); err != nil {
		return nil, err
	}

	ct, err := c.encrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, err
	}

	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             ct,
	}, nil
}

// handleDecrypt decrypts in one part. Multi-part requests are refused.
func handleDecrypt(ctx context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := refuseMultiPart("Decrypt", req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	if len(req.Data) == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Data (ciphertext) is required")
	}
	if err := refuseCipherOptions("Decrypt", req.CryptographicParameters, req.IVCounterNonce, req.AuthenticatedEncryptionAdditionalData); err != nil {
		return nil, err
	}

	pt, err := c.decrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, err
	}

	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             pt,
	}, nil
}

func handleSign(ctx context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := refuseMultiPart("Sign", req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	// Only Data is accepted. DigestedData is not supported.
	if len(req.Data) == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Data (input to sign) is required")
	}
	if req.CryptographicParameters != nil {
		return nil, operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Sign")
	}

	sig, err := c.sign(ctx, uid, req.Data)
	if err != nil {
		return nil, err
	}

	return &payloads.SignResponsePayload{
		UniqueIdentifier: uid,
		SignatureData:    sig,
	}, nil
}

func handleVerify(ctx context.Context, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	c, uid, err := beginOn(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if err := refuseMultiPart("SignatureVerify", req.CorrelationValue, req.InitIndicator, req.FinalIndicator); err != nil {
		return nil, err
	}
	// Only Data is accepted. DigestedData is not supported.
	if len(req.Data) == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Data is required")
	}
	if len(req.SignatureData) == 0 {
		return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "SignatureData is required")
	}
	if req.CryptographicParameters != nil {
		return nil, operationErrorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for SignatureVerify")
	}

	valid, err := c.verify(ctx, uid, req.Data, req.SignatureData)
	if err != nil {
		return nil, err
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

// templateValue returns the value of the template's first attribute name
// that has the type T, or the zero value.
func templateValue[T any](ta kmiplib.TemplateAttribute, name kmiplib.AttributeName) T {
	for _, attr := range ta.Attribute {
		if v, ok := attr.AttributeValue.(T); ok && attr.AttributeName == name {
			return v
		}
	}
	var zero T
	return zero
}
