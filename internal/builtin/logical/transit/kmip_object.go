package transit

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const kmipObjectStoragePrefix = "kmip/object/"

// KMIP object types supported by this PoC.
const (
	kmipObjectTypeSymmetricKey = "SymmetricKey"
)

// KMIP lifecycle states, using the KMIP 1.x enumeration names.
const (
	kmipStatePreActive            = "PreActive"
	kmipStateActive               = "Active"
	kmipStateDeactivated          = "Deactivated"
	kmipStateCompromised          = "Compromised"
	kmipStateDestroyed            = "Destroyed"
	kmipStateDestroyedCompromised = "DestroyedCompromised"
)

type kmipObject struct {
	ID         string `json:"id"`
	ObjectType string `json:"object_type"`
	Origin     string `json:"origin"` // "created" or "registered"

	// Backing Transit key.
	// KeyVersion is pinned: a KMIP object is immutable key material,
	// so a Transit rotation must not change what Get returns.
	KeyName    string `json:"key_name"`
	KeyVersion int    `json:"key_version"`

	Algorithm string `json:"algorithm"`
	Length    int    `json:"length"`
	UsageMask int64  `json:"usage_mask"`

	State string `json:"state"`

	// Custom attributes support
	CustomAttributes map[string][]string `json:"custom_attributes,omitempty"`

	// Unix seconds; zero means unset. KMIP Date-Time has second precision.
	InitialDate              int64 `json:"initial_date"`
	ActivationDate           int64 `json:"activation_date,omitempty"`
	DeactivationDate         int64 `json:"deactivation_date,omitempty"`
	DestroyDate              int64 `json:"destroy_date,omitempty"`
	CompromiseOccurrenceDate int64 `json:"compromise_occurrence_date,omitempty"`
	CompromiseDate           int64 `json:"compromise_date,omitempty"`
	LastChangeDate           int64 `json:"last_change_date"`
}

func (o *kmipObject) toKmipResponseData() map[string]any {
	data := map[string]any{
		"id":               o.ID,
		"object_type":      o.ObjectType,
		"origin":           o.Origin,
		"key_name":         o.KeyName,
		"key_version":      o.KeyVersion,
		"algorithm":        o.Algorithm,
		"length":           o.Length,
		"usage_mask":       o.UsageMask,
		"state":            o.State,
		"initial_date":     o.InitialDate,
		"last_change_date": o.LastChangeDate,
	}
	custom := map[string][]string{}
	for k, v := range o.CustomAttributes {
		custom[k] = slices.Clone(v)
	}
	data["custom_attributes"] = custom

	optional := map[string]int64{
		"activation_date":            o.ActivationDate,
		"deactivation_date":          o.DeactivationDate,
		"destroy_date":               o.DestroyDate,
		"compromise_occurrence_date": o.CompromiseOccurrenceDate,
		"compromise_date":            o.CompromiseDate,
	}
	for k, v := range optional {
		if v != 0 {
			data[k] = v
		}
	}
	return data
}

func (o *kmipObject) isDestroyed() bool {
	return o.State == kmipStateDestroyed || o.State == kmipStateDestroyedCompromised
}

func (o *kmipObject) updateLastChangeDate(now time.Time) {
	o.LastChangeDate = now.Unix()
}

func kmipObjectPath(id string) string {
	return kmipObjectStoragePrefix + id
}

// kmipKeyType maps a KMIP algorithm/length pair onto a Transit key type.
func kmipKeyType(algorithm string, length int) (keysutil.KeyType, error) {
	if !strings.EqualFold(algorithm, "AES") {
		return 0, logical.CodedError(http.StatusNotImplemented, "unsupported cryptographic algorithm %q: only AES is supported", algorithm)
	}
	switch length {
	case 128:
		return keysutil.KeyType_AES128_GCM96, nil
	case 256:
		return keysutil.KeyType_AES256_GCM96, nil
	default:
		return 0, logical.CodedError(http.StatusNotImplemented, "unsupported AES key length %d: only 128 and 256 are supported", length)
	}
}

func (b *backend) storeKMIPObject(ctx context.Context, s logical.Storage, obj *kmipObject) error {
	entry, err := logical.StorageEntryJSON(kmipObjectPath(obj.ID), obj)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) loadKMIPObject(ctx context.Context, s logical.Storage, id string) (*kmipObject, error) {
	if id == "" {
		return nil, logical.CodedError(http.StatusBadRequest, "missing object unique identifier")
	}
	entry, err := s.Get(ctx, kmipObjectPath(id))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, logical.CodedError(http.StatusNotFound, "KMIP object %q not found", id)
	}
	var obj kmipObject
	if err := jsonutil.DecodeJSON(entry.Value, &obj); err != nil {
		return nil, fmt.Errorf("failed to decode KMIP object %q: %w", id, err)
	}
	return &obj, nil
}

func (b *backend) listKMIPObjectIDs(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, kmipObjectStoragePrefix)
}
