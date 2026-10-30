// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strconv"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	metadataMaxBytes      = 64 << 10
	metadataMaxValueBytes = 8 << 10
	metadataMaxKeyBytes   = 512
	metadataMaxKeys       = 1024
)

func (b *backend) pathKeysMetadata() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/metadata",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "key-metadata",
		},
		Fields: map[string]*framework.FieldSchema{
			"name":            {Type: framework.TypeString, Description: "Name of the key"},
			"custom_metadata": {Type: framework.TypeMap, Description: "Custom string key-value pairs. PATCH accepts null to remove a key."},
			// Decode cas from Raw below. A string schema lets JSON numbers
			// pass validation across the full uint64 version range.
			"cas": {Type: framework.TypeString, Description: "Optional integer metadata version; 0 requires an absent record."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathKeysMetadataRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathKeysMetadataWrite},
			logical.PatchOperation:  &framework.PathOperation{Callback: b.pathKeysMetadataWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathKeysMetadataWrite},
		},
		HelpSynopsis:    pathKeysMetadataHelpSyn,
		HelpDescription: pathKeysMetadataHelpDesc,
	}
}

func metadataResponse(record *keysutil.MetadataRecord) *logical.Response {
	if record == nil {
		record = &keysutil.MetadataRecord{Data: map[string]string{}}
	}
	return &logical.Response{Data: map[string]any{"custom_metadata": record.Data, "version": record.Version}}
}

func (b *backend) pathKeysMetadataRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    d.Get("name").(string),
	}, b.GetRandomReader())
	if err != nil || p == nil {
		return nil, err
	}
	defer p.Unlock()
	record, err := p.LoadMetadata(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return metadataResponse(record), nil
}

func (b *backend) pathKeysMetadataWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	p, _, err := b.GetPolicyExclusive(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    d.Get("name").(string),
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	defer p.Unlock()

	// A delete can finish while GetPolicyExclusive waits for the lock.
	// StoreMetadata also refuses a policy marked deleted. Check storage so
	// no record is written for a key that no longer exists there.
	if entry, err := req.Storage.Get(ctx, path.Join(p.StoragePrefix, "policy", p.Name)); err != nil {
		return nil, err
	} else if entry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	record, err := p.LoadMetadata(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if req.Operation != logical.DeleteOperation {
		if raw, ok := d.Raw["cas"]; ok {
			cas, err := strconv.ParseUint(fmt.Sprint(raw), 10, 64)
			if err != nil {
				return logical.ErrorResponse("cas must be a non-negative integer"), logical.ErrInvalidRequest
			}
			if (cas == 0 && record != nil) || (cas != 0 && (record == nil || cas != record.Version)) {
				return logical.ErrorResponse("check-and-set parameter did not match the current version"), logical.ErrInvalidRequest
			}
		}
	}
	if record == nil {
		record = &keysutil.MetadataRecord{Data: map[string]string{}}
	}
	if record.Version == math.MaxUint64 {
		return logical.ErrorResponse("metadata version overflow"), logical.ErrInvalidRequest
	}
	data := map[string]string{}
	if req.Operation == logical.PatchOperation {
		data = record.Data
	}
	if req.Operation != logical.DeleteOperation {
		if raw, ok := d.Raw["custom_metadata"]; ok {
			buf, err := json.Marshal(raw)
			if err != nil {
				return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
			}
			var changes map[string]any
			if err := json.Unmarshal(buf, &changes); err != nil || changes == nil {
				return logical.ErrorResponse("custom_metadata must be an object"), logical.ErrInvalidRequest
			}
			for key, value := range changes {
				if value == nil && req.Operation == logical.PatchOperation {
					delete(data, key)
					continue
				}
				text, ok := value.(string)
				if !ok {
					return logical.ErrorResponse("custom_metadata values must be strings"), logical.ErrInvalidRequest
				}
				data[key] = text
			}
		}
	}
	record.Data = data
	record.Version++
	if err := checkMetadataBounds(record); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := p.StoreMetadata(ctx, req.Storage, record); err != nil {
		return nil, err
	}
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}
	return metadataResponse(record), nil
}

func checkMetadataBounds(record *keysutil.MetadataRecord) error {
	if len(record.Data) > metadataMaxKeys {
		return fmt.Errorf("metadata holds %d keys; the limit is %d", len(record.Data), metadataMaxKeys)
	}
	for key, value := range record.Data {
		if len(key) == 0 || len(key) > metadataMaxKeyBytes {
			return fmt.Errorf("metadata keys must contain 1 to %d bytes", metadataMaxKeyBytes)
		}
		if len(value) > metadataMaxValueBytes {
			return fmt.Errorf("metadata value for %q is %d bytes; the limit is %d", key, len(value), metadataMaxValueBytes)
		}
	}
	buf, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(buf) > metadataMaxBytes {
		return fmt.Errorf("metadata is %d bytes; the limit is %d", len(buf), metadataMaxBytes)
	}
	return nil
}

const (
	pathKeysMetadataHelpSyn  = `Read or change a named key's custom metadata`
	pathKeysMetadataHelpDesc = `
GET returns custom_metadata and version. POST replaces the string map, PATCH
merges it (null removes a key), and DELETE clears it. Each write increments
the version, including a clear. Optional cas on POST and PATCH must match the
version; cas=0 requires an absent record. Only deleting the key removes the
record and resets the version. The record is limited to 64 KiB serialized,
1024 keys, 512 bytes per non-empty key and 8 KiB per value.
`
)
