package kmip

import (
	"context"
	"encoding/base64"
	"slices"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// supportedOperations is reported by Query and registered as routes.
// Discover Versions is answered by the library's batch executor.
var supportedOperations = []kmip.Operation{
	kmip.OperationCreate,
	kmip.OperationRegister,
	kmip.OperationLocate,
	kmip.OperationGet,
	kmip.OperationGetAttributes,
	kmip.OperationGetAttributeList,
	kmip.OperationAddAttribute,
	kmip.OperationModifyAttribute,
	kmip.OperationDeleteAttribute,
	kmip.OperationActivate,
	kmip.OperationRevoke,
	kmip.OperationDestroy,
	kmip.OperationQuery,
	kmip.OperationDiscoverVersions,
}

func (s *Server) routes(exec *kmipserver.BatchExecutor) {
	exec.Route(kmip.OperationCreate, kmipserver.HandleFunc(s.create))
	exec.Route(kmip.OperationRegister, kmipserver.HandleFunc(s.register))
	exec.Route(kmip.OperationLocate, kmipserver.HandleFunc(s.locate))
	exec.Route(kmip.OperationGet, kmipserver.HandleFunc(s.get))
	exec.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(s.getAttributes))
	exec.Route(kmip.OperationGetAttributeList, kmipserver.HandleFunc(s.getAttributeList))
	exec.Route(kmip.OperationAddAttribute, kmipserver.HandleFunc(s.addAttribute))
	exec.Route(kmip.OperationModifyAttribute, kmipserver.HandleFunc(s.modifyAttribute))
	exec.Route(kmip.OperationDeleteAttribute, kmipserver.HandleFunc(s.deleteAttribute))
	exec.Route(kmip.OperationActivate, kmipserver.HandleFunc(s.activate))
	exec.Route(kmip.OperationRevoke, kmipserver.HandleFunc(s.revoke))
	exec.Route(kmip.OperationDestroy, kmipserver.HandleFunc(s.destroy))
	exec.Route(kmip.OperationQuery, kmipserver.HandleFunc(s.query))
}

// Key Operations
func (s *Server) create(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	if req.ObjectType != kmip.ObjectTypeSymmetricKey {
		return nil, notSymmetric(req.ObjectType)
	}
	data, err := parseTemplate(req.TemplateAttribute)
	if err != nil {
		return nil, err
	}
	if _, ok := data["algorithm"]; !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonMissingData, "Cryptographic Algorithm is required")
	}
	if _, ok := data["length"]; !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonMissingData, "Cryptographic Length is required")
	}

	out, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/create", data)
	if err != nil {
		return nil, err
	}
	id := asString(out["id"])
	kmipserver.SetIdPlaceholder(ctx, id)
	return &payloads.CreateResponsePayload{ObjectType: kmip.ObjectTypeSymmetricKey, UniqueIdentifier: id}, nil
}

func (s *Server) get(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	id, err := resolveId(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if req.KeyWrappingSpecification != nil || req.KeyWrapType != 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "key wrapping is not supported")
	}
	if req.KeyCompressionType != 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "key compression is not supported")
	}

	format := req.KeyFormatType
	if format == 0 {
		format = kmip.KeyFormatTypeRaw
	}
	if format != kmip.KeyFormatTypeRaw && format != kmip.KeyFormatTypeTransparentSymmetricKey {
		return nil, kmipserver.Errorf(kmip.ResultReasonKeyFormatTypeNotSupported, "key format %s is not supported for symmetric keys", ttlv.EnumStr(format))
	}

	out, err := s.handleTransitOperation(ctx, logical.ReadOperation, "kmip/object/"+id+"/material", nil)
	if err != nil {
		return nil, err
	}
	material, err := base64.StdEncoding.DecodeString(asString(out["key_material"]))
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "invalid key material returned by handleTransitOperation")
	}

	var km kmip.KeyMaterial
	if format == kmip.KeyFormatTypeRaw {
		km.Bytes = &material
	} else {
		km.TransparentSymmetricKey = &kmip.TransparentSymmetricKey{Key: material}
	}

	return &payloads.GetResponsePayload{
		ObjectType:       kmip.ObjectTypeSymmetricKey,
		UniqueIdentifier: id,
		Object: &kmip.SymmetricKey{KeyBlock: kmip.KeyBlock{
			KeyFormatType:          format,
			KeyValue:               &kmip.KeyValue{Plain: &kmip.PlainKeyValue{KeyMaterial: km}},
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			CryptographicLength:    int32(asInt64(out["length"])),
		}},
	}, nil
}

func (s *Server) register(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	if req.ObjectType != kmip.ObjectTypeSymmetricKey {
		return nil, notSymmetric(req.ObjectType)
	}
	key, ok := req.Object.(*kmip.SymmetricKey)
	if !ok || key == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "object is not a Symmetric Key")
	}
	kb := key.KeyBlock
	if kb.KeyWrappingData != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "registering wrapped key material is not supported")
	}
	if kb.KeyCompressionType != 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "key compression is not supported")
	}
	material, err := key.KeyMaterial()
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonKeyFormatTypeNotSupported, "%s", err)
	}

	data, err := parseTemplate(req.TemplateAttribute)
	if err != nil {
		return nil, err
	}
	// The key block is authoritative for algorithm and length.
	if kb.CryptographicAlgorithm != 0 {
		data["algorithm"] = ttlv.EnumStr(kb.CryptographicAlgorithm)
	}
	if kb.CryptographicLength != 0 {
		data["length"] = int(kb.CryptographicLength)
	}
	if _, ok := data["algorithm"]; !ok {
		return nil, kmipserver.Errorf(kmip.ResultReasonMissingData, "Cryptographic Algorithm is required")
	}
	data["key_material"] = base64.StdEncoding.EncodeToString(material)

	out, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/register", data)
	if err != nil {
		return nil, err
	}
	id := asString(out["id"])
	kmipserver.SetIdPlaceholder(ctx, id)
	return &payloads.RegisterResponsePayload{UniqueIdentifier: id}, nil
}

func (s *Server) activate(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	id, err := resolveId(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if _, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/object/"+id+"/activate", nil); err != nil {
		return nil, err
	}
	return &payloads.ActivateResponsePayload{UniqueIdentifier: id}, nil
}

func (s *Server) revoke(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	id, err := resolveId(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if req.RevocationReason.RevocationReasonCode == 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonMissingData, "Revocation Reason Code is required")
	}
	data := map[string]any{
		"reason_code": int(req.RevocationReason.RevocationReasonCode),
		"message":     req.RevocationReason.RevocationMessage,
	}
	if req.CompromiseOccurrenceDate != nil {
		data["compromise_occurrence_date"] = req.CompromiseOccurrenceDate.Unix()
	}
	if _, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/object/"+id+"/revoke", data); err != nil {
		return nil, err
	}
	return &payloads.RevokeResponsePayload{UniqueIdentifier: id}, nil
}

func (s *Server) destroy(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	id, err := resolveId(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if _, err := s.handleTransitOperation(ctx, logical.DeleteOperation, "kmip/object/"+id, nil); err != nil {
		return nil, err
	}
	return &payloads.DestroyResponsePayload{UniqueIdentifier: id}, nil
}

func (s *Server) locate(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	empty := func() *payloads.LocateResponsePayload {
		zero := int32(0)
		return &payloads.LocateResponsePayload{LocatedItems: &zero}
	}

	// Nothing is ever archived.
	if req.StorageStatusMask != 0 && req.StorageStatusMask&kmip.StorageStatusOnlineStorage == 0 {
		return empty(), nil
	}

	data := map[string]any{}
	var names, groups []string
	custom := map[string]any{}

	for _, attr := range req.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameObjectType:
			ot, ok := attr.AttributeValue.(kmip.ObjectType)
			if !ok {
				return nil, invalidAttr(attr)
			}
			if ot != kmip.ObjectTypeSymmetricKey {
				return empty(), nil
			}
		case kmip.AttributeNameCryptographicAlgorithm:
			alg, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm)
			if !ok {
				return nil, invalidAttr(attr)
			}
			if alg != kmip.CryptographicAlgorithmAES {
				return empty(), nil
			}
		case kmip.AttributeNameCryptographicLength:
			l, ok := attr.AttributeValue.(int32)
			if !ok {
				return nil, invalidAttr(attr)
			}
			data["length"] = int(l)
		case kmip.AttributeNameCryptographicUsageMask:
			m, ok := attr.AttributeValue.(kmip.CryptographicUsageMask)
			if !ok {
				return nil, invalidAttr(attr)
			}
			data["usage_mask"] = int64(m)
		case kmip.AttributeNameState:
			st, ok := attr.AttributeValue.(kmip.State)
			if !ok {
				return nil, invalidAttr(attr)
			}
			name, ok := stateFromKMIP(st)
			if !ok {
				return empty(), nil
			}
			data["state"] = name
		case kmip.AttributeNameName:
			n, ok := attr.AttributeValue.(kmip.Name)
			if !ok {
				return nil, invalidAttr(attr)
			}
			names = append(names, n.NameValue)
		case kmip.AttributeNameObjectGroup:
			g, ok := attr.AttributeValue.(string)
			if !ok {
				return nil, invalidAttr(attr)
			}
			groups = append(groups, g)
		default:
			if !attr.AttributeName.IsCustom() {
				return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "Locate by attribute %q is not supported", attr.AttributeName)
			}
			v, err := customValue(attr)
			if err != nil {
				return nil, err
			}
			prev, _ := custom[string(attr.AttributeName)].([]string)
			custom[string(attr.AttributeName)] = append(prev, v)
		}
	}
	if len(names) > 0 {
		data["names"] = names
	}
	if len(groups) > 0 {
		data["object_groups"] = groups
	}
	if len(custom) > 0 {
		data["custom_attributes"] = custom
	}
	if req.MaximumItems > 0 {
		data["max_items"] = int(req.MaximumItems)
	}
	if req.OffsetItems > 0 {
		data["offset_items"] = int(req.OffsetItems)
	}

	out, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/locate", data)
	if err != nil {
		return nil, err
	}
	ids := asStrings(out["ids"])
	total := int32(asInt64(out["located_items"]))
	if len(ids) == 1 {
		kmipserver.SetIdPlaceholder(ctx, ids[0])
	}
	return &payloads.LocateResponsePayload{UniqueIdentifier: ids, LocatedItems: &total}, nil
}

// Attributes Operations
func (s *Server) getAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	id, attrs, err := s.readAttributes(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	if len(req.AttributeName) > 0 {
		attrs = slices.DeleteFunc(attrs, func(a kmip.Attribute) bool {
			return !slices.Contains(req.AttributeName, a.AttributeName)
		})
	}
	return &payloads.GetAttributesResponsePayload{UniqueIdentifier: id, Attribute: attrs}, nil
}

func (s *Server) getAttributeList(ctx context.Context, req *payloads.GetAttributeListRequestPayload) (*payloads.GetAttributeListResponsePayload, error) {
	id, attrs, err := s.readAttributes(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, err
	}
	var names []kmip.AttributeName
	for _, a := range attrs {
		if !slices.Contains(names, a.AttributeName) {
			names = append(names, a.AttributeName)
		}
	}
	return &payloads.GetAttributeListResponsePayload{UniqueIdentifier: id, AttributeName: names}, nil
}

func (s *Server) addAttribute(ctx context.Context, req *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
	value, err := textValue(req.Attribute)
	if err != nil {
		return nil, err
	}
	id, attr, err := s.changeAttribute(ctx, req.UniqueIdentifier, "add", req.Attribute.AttributeName, value, 0)
	if err != nil {
		return nil, err
	}
	return &payloads.AddAttributeResponsePayload{UniqueIdentifier: id, Attribute: attr}, nil
}

func (s *Server) modifyAttribute(ctx context.Context, req *payloads.ModifyAttributeRequestPayload) (*payloads.ModifyAttributeResponsePayload, error) {
	value, err := textValue(req.Attribute)
	if err != nil {
		return nil, err
	}
	id, attr, err := s.changeAttribute(ctx, req.UniqueIdentifier, "modify", req.Attribute.AttributeName, value, attrIndex(req.Attribute))
	if err != nil {
		return nil, err
	}
	return &payloads.ModifyAttributeResponsePayload{UniqueIdentifier: id, Attribute: attr}, nil
}

func (s *Server) deleteAttribute(ctx context.Context, req *payloads.DeleteAttributeRequestPayload) (*payloads.DeleteAttributeResponsePayload, error) {
	index := 0
	if req.AttributeIndex != nil {
		index = int(*req.AttributeIndex)
	}
	id, attr, err := s.changeAttribute(ctx, req.UniqueIdentifier, "delete", req.AttributeName, "", index)
	if err != nil {
		return nil, err
	}
	return &payloads.DeleteAttributeResponsePayload{UniqueIdentifier: id, Attribute: attr}, nil
}

func (s *Server) readAttributes(ctx context.Context, reqID string) (string, []kmip.Attribute, error) {
	id, err := resolveId(ctx, reqID)
	if err != nil {
		return "", nil, err
	}
	out, err := s.handleTransitOperation(ctx, logical.ReadOperation, "kmip/object/"+id, nil)
	if err != nil {
		return "", nil, err
	}
	attrs, err := objectAttributes(out)
	if err != nil {
		return "", nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%s", err)
	}
	return id, attrs, nil
}

func (s *Server) changeAttribute(ctx context.Context, reqID, action string, name kmip.AttributeName, value string, index int) (string, kmip.Attribute, error) {
	id, err := resolveId(ctx, reqID)
	if err != nil {
		return "", kmip.Attribute{}, err
	}
	out, err := s.handleTransitOperation(ctx, logical.UpdateOperation, "kmip/object/"+id+"/attribute", map[string]any{
		"action": action,
		"name":   string(name),
		"value":  value,
		"index":  index,
	})
	if err != nil {
		return "", kmip.Attribute{}, err
	}
	attr := textAttribute(name, int(asInt64(out["attribute_index"])), asString(out["attribute_value"]))
	return id, attr, nil
}

func (s *Server) query(_ context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	resp := &payloads.QueryResponsePayload{}
	for _, fn := range req.QueryFunction {
		switch fn {
		case kmip.QueryFunctionOperations:
			resp.Operations = slices.Clone(supportedOperations)
		case kmip.QueryFunctionObjects:
			resp.ObjectType = []kmip.ObjectType{kmip.ObjectTypeSymmetricKey}
		case kmip.QueryFunctionServerInformation:
			resp.VendorIdentification = "OpenBao"
		}
	}
	return resp, nil
}

func notSymmetric(ot kmip.ObjectType) error {
	return kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "object type %s is not supported; only SymmetricKey is", ttlv.EnumStr(ot))
}

func attrIndex(attr kmip.Attribute) int {
	if attr.AttributeIndex == nil {
		return 0
	}
	return int(*attr.AttributeIndex)
}
