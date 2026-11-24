package kmip

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// Lifecycle states as stored by Transit, mapped onto KMIP enumerations.
var stateToKMIP = map[string]kmip.State{
	"PreActive":            kmip.StatePreActive,
	"Active":               kmip.StateActive,
	"Deactivated":          kmip.StateDeactivated,
	"Compromised":          kmip.StateCompromised,
	"Destroyed":            kmip.StateDestroyed,
	"DestroyedCompromised": kmip.StateDestroyedCompromised,
}

func stateFromKMIP(st kmip.State) (string, bool) {
	for k, v := range stateToKMIP {
		if v == st {
			return k, true
		}
	}
	return "", false
}

// parseTemplate converts a KMIP Template-Attribute into the field map
// accepted by transit's kmip/create and kmip/register endpoints.
func parseTemplate(tpl kmip.TemplateAttribute) (map[string]any, error) {
	if len(tpl.Name) > 0 {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "Template objects are not supported; use individual attributes")
	}

	data := map[string]any{}
	var names, groups []string
	custom := map[string]any{}

	for _, attr := range tpl.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameCryptographicAlgorithm:
			alg, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm)
			if !ok {
				return nil, invalidAttr(attr)
			}
			data["algorithm"] = ttlv.EnumStr(alg)
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
		case kmip.AttributeNameName:
			n, ok := attr.AttributeValue.(kmip.Name)
			if !ok || n.NameValue == "" {
				return nil, invalidAttr(attr)
			}
			names = append(names, n.NameValue)
		case kmip.AttributeNameObjectGroup:
			g, ok := attr.AttributeValue.(string)
			if !ok {
				return nil, invalidAttr(attr)
			}
			groups = append(groups, g)
		case kmip.AttributeNameContactInformation:
			c, ok := attr.AttributeValue.(string)
			if !ok {
				return nil, invalidAttr(attr)
			}
			data["contact_information"] = c
		case kmip.AttributeNameActivationDate:
			t, ok := attr.AttributeValue.(time.Time)
			if !ok {
				return nil, invalidAttr(attr)
			}
			data["activation_date"] = t.Unix()
		default:
			if slices.Contains(ignoredTemplateAttributes, attr.AttributeName) {
				continue
			}
			if attr.AttributeName.IsCustom() {
				v, err := customValue(attr)
				if err != nil {
					return nil, err
				}
				prev, _ := custom[string(attr.AttributeName)].([]string)
				custom[string(attr.AttributeName)] = append(prev, v)
				continue
			}
			return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "attribute %q cannot be set by the client", attr.AttributeName)
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
	return data, nil
}

func invalidAttr(attr kmip.Attribute) error {
	return kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid value for attribute %q", attr.AttributeName)
}

// customValue extracts the text value of a custom (x-) attribute.
func customValue(attr kmip.Attribute) (string, error) {
	if !attr.AttributeName.IsCustom() || attr.AttributeName[0] != 'x' {
		return "", kmipserver.Errorf(kmip.ResultReasonInvalidField, "client custom attributes must start with \"x-\"")
	}
	switch v := attr.AttributeValue.(type) {
	case string:
		return v, nil
	case ttlv.Value:
		if s, ok := v.Value.(string); ok {
			return s, nil
		}
	case *ttlv.Value:
		if s, ok := v.Value.(string); ok {
			return s, nil
		}
	}
	return "", kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "custom attribute %q: only Text String values are supported", attr.AttributeName)
}

// textValue extracts the client-modifiable text value of an attribute for
// Add/Modify Attribute.
func textValue(attr kmip.Attribute) (string, error) {
	if attr.AttributeName == kmip.AttributeNameName {
		n, ok := attr.AttributeValue.(kmip.Name)
		if !ok || n.NameValue == "" {
			return "", invalidAttr(attr)
		}
		return n.NameValue, nil
	}
	if attr.AttributeName.IsCustom() {
		return customValue(attr)
	}
	return "", kmipserver.Errorf(kmip.ResultReasonInvalidField, "attribute %q cannot be modified by the client", attr.AttributeName)
}

// textAttribute builds the KMIP attribute carrying a client-modifiable text
// value, as returned from Add/Modify/Delete Attribute.
func textAttribute(name kmip.AttributeName, index int, value string) kmip.Attribute {
	idx := int32(index)
	var v any = value
	if name == kmip.AttributeNameName {
		v = kmip.Name{NameValue: value, NameType: kmip.NameTypeUninterpretedTextString}
	}
	return kmip.Attribute{AttributeName: name, AttributeIndex: &idx, AttributeValue: v}
}

// objectAttributes renders the object record returned by transit as KMIP
// attributes. Only attributes defined in KMIP 1.0 are emitted, so the same
// set is valid for every supported protocol version.
func objectAttributes(data map[string]any) ([]kmip.Attribute, error) {
	var attrs []kmip.Attribute
	add := func(name kmip.AttributeName, value any) {
		attrs = append(attrs, kmip.Attribute{AttributeName: name, AttributeValue: value})
	}
	addIndexed := func(name kmip.AttributeName, values []string) {
		for i, v := range values {
			attrs = append(attrs, textAttribute(name, i, v))
		}
	}

	id := asString(data["id"])
	add(kmip.AttributeNameUniqueIdentifier, id)
	add(kmip.AttributeNameObjectType, kmip.ObjectTypeSymmetricKey)
	add(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES)
	add(kmip.AttributeNameCryptographicLength, int32(asInt64(data["length"])))
	add(kmip.AttributeNameCryptographicUsageMask, kmip.CryptographicUsageMask(asInt64(data["usage_mask"])))

	st, ok := stateToKMIP[asString(data["state"])]
	if !ok {
		return nil, fmt.Errorf("object %q has unknown state %q", id, data["state"])
	}
	add(kmip.AttributeNameState, st)

	addIndexed(kmip.AttributeNameName, asStrings(data["names"]))
	addIndexed(kmip.AttributeNameObjectGroup, asStrings(data["object_groups"]))
	if c := asString(data["contact_information"]); c != "" {
		add(kmip.AttributeNameContactInformation, c)
	}

	dates := []struct {
		field string
		name  kmip.AttributeName
	}{
		{"initial_date", kmip.AttributeNameInitialDate},
		{"activation_date", kmip.AttributeNameActivationDate},
		{"deactivation_date", kmip.AttributeNameDeactivationDate},
		{"destroy_date", kmip.AttributeNameDestroyDate},
		{"compromise_occurrence_date", kmip.AttributeNameCompromiseOccurrenceDate},
		{"compromise_date", kmip.AttributeNameCompromiseDate},
		{"last_change_date", kmip.AttributeNameLastChangeDate},
	}
	for _, d := range dates {
		if ts := asInt64(data[d.field]); ts != 0 {
			add(d.name, time.Unix(ts, 0).UTC())
		}
	}

	if code := asInt64(data["revocation_reason_code"]); code != 0 {
		add(kmip.AttributeNameRevocationReason, kmip.RevocationReason{
			RevocationReasonCode: kmip.RevocationReasonCode(code),
			RevocationMessage:    asString(data["revocation_message"]),
		})
	}

	custom := asStringsMap(data["custom_attributes"])
	names := make([]string, 0, len(custom))
	for k := range custom {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		addIndexed(kmip.AttributeName(n), custom[n])
	}
	return attrs, nil
}

// The converters below accept both the native Go types produced by the
// in-process builtin Transit backend and the JSON-decoded types an external
// plugin would return.

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func asStrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func asStringsMap(v any) map[string][]string {
	switch m := v.(type) {
	case map[string][]string:
		return m
	case map[string]any:
		out := make(map[string][]string, len(m))
		for k, e := range m {
			out[k] = asStrings(e)
		}
		return out
	}
	return nil
}
