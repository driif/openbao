// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Bounds on a key's metadata record. The total is the real bound; the
// others fail early with a precise error. Restore checks none of them.
const (
	metadataMaxBytes      = 64 << 10
	metadataMaxScopes     = 8
	metadataMaxEntries    = 128
	metadataMaxValueBytes = 8 << 10
)

var metadataKeyNameRegex = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")

// metadataRecord is a key's metadata: scope, then entry, then values.
type metadataRecord map[string]map[string][]string

// metadataOperation is one change to a metadata record.
type metadataOperation struct {
	Op       string `json:"op"`
	Scope    string `json:"scope"`
	Entry    string `json:"entry"`
	Value    string `json:"value"`
	Index    *int   `json:"index"`
	Expected string `json:"expected"`
}

func (b *backend) pathKeysMetadata() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/metadata",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "key-metadata",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"operations": {
				Type: framework.TypeSlice,
				Description: `Ordered list of changes to apply. Each item has an
"op" of "add", "delete", "claim" or "link", a "scope" and an "entry".
"add" appends "value" to the entry. "delete" removes the entry, or only
the value at "index" when given. "claim" sets the entry to the single
"value" when the entry is absent, already holds "value", or holds
"expected". "link" sets the entry to the single "value", which must be a
key name. The list applies whole or not at all.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeysMetadataRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeysMetadataWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
			},
		},

		HelpSynopsis:    pathKeysMetadataHelpSyn,
		HelpDescription: pathKeysMetadataHelpDesc,
	}
}

func (b *backend) pathKeysMetadataRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	defer p.Unlock()

	record, err := loadMetadataRecord(ctx, req.Storage, p)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"metadata": record}}, nil
}

func (b *backend) pathKeysMetadataWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	name := d.Get("name").(string)

	ops, err := decodeMetadataOperations(d.Raw["operations"])
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	p, _, err := b.GetPolicyExclusive(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	defer p.Unlock()

	// GetPolicyExclusive checks for a deleted key before it waits for the
	// lock, so a delete can finish while this request waits. StoreMetadata
	// refuses a policy marked deleted; this read also refuses a key that is
	// gone from storage, so no record is left for the next key of this name.
	if entry, err := req.Storage.Get(ctx, path.Join(p.StoragePrefix, "policy", p.Name)); err != nil {
		return nil, err
	} else if entry == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}

	record, err := loadMetadataRecord(ctx, req.Storage, p)
	if err != nil {
		return nil, err
	}
	for i, op := range ops {
		if err := record.apply(op); err != nil {
			return logical.ErrorResponse("operation %d: %s", i, err), logical.ErrInvalidRequest
		}
	}
	encoded, err := record.encode()
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if err := p.StoreMetadata(ctx, req.Storage, encoded); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{"metadata": record}}, nil
}

func loadMetadataRecord(ctx context.Context, s logical.Storage, p *keysutil.Policy) (metadataRecord, error) {
	raw, err := p.LoadMetadata(ctx, s)
	if err != nil {
		return nil, err
	}
	record := metadataRecord{}
	if len(raw) == 0 {
		return record, nil
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("decoding metadata of key %q: %w", p.Name, err)
	}
	return record, nil
}

func decodeMetadataOperations(raw any) ([]metadataOperation, error) {
	if raw == nil {
		return nil, nil
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var ops []metadataOperation
	if err := dec.Decode(&ops); err != nil {
		return nil, fmt.Errorf("invalid operations: %w", err)
	}
	return ops, nil
}

func (r metadataRecord) apply(op metadataOperation) error {
	if op.Scope == "" || op.Entry == "" {
		return fmt.Errorf("%q needs a scope and an entry", op.Op)
	}
	values := r[op.Scope][op.Entry]

	switch op.Op {
	case "add":
		r.set(op.Scope, op.Entry, append(values, op.Value))

	case "delete":
		if op.Index == nil {
			r.set(op.Scope, op.Entry, nil)
			return nil
		}
		i := *op.Index
		if i < 0 || i >= len(values) {
			return fmt.Errorf("entry %q in scope %q has no value at index %d", op.Entry, op.Scope, i)
		}
		r.set(op.Scope, op.Entry, slices.Delete(slices.Clone(values), i, i+1))

	case "claim":
		switch {
		case len(values) == 0,
			len(values) == 1 && values[0] == op.Value,
			len(values) == 1 && op.Expected != "" && values[0] == op.Expected:
			r.set(op.Scope, op.Entry, []string{op.Value})
		default:
			return fmt.Errorf("entry %q in scope %q is held by %q", op.Entry, op.Scope, strings.Join(values, ","))
		}

	case "link":
		if !metadataKeyNameRegex.MatchString(op.Value) {
			return fmt.Errorf("link value %q is not a key name", op.Value)
		}
		r.set(op.Scope, op.Entry, []string{op.Value})

	default:
		return fmt.Errorf("unknown op %q: use add, delete, claim or link", op.Op)
	}
	return nil
}

// set replaces an entry's values, dropping the entry and then the scope
// when they become empty.
func (r metadataRecord) set(scope, entry string, values []string) {
	if len(values) > 0 {
		if r[scope] == nil {
			r[scope] = map[string][]string{}
		}
		r[scope][entry] = values
		return
	}
	delete(r[scope], entry)
	if len(r[scope]) == 0 {
		delete(r, scope)
	}
}

// encode checks the bounds and marshals the record. An empty record
// encodes to nothing, which deletes it.
func (r metadataRecord) encode() ([]byte, error) {
	if len(r) == 0 {
		return nil, nil
	}
	if len(r) > metadataMaxScopes {
		return nil, fmt.Errorf("metadata holds %d scopes; the limit is %d", len(r), metadataMaxScopes)
	}
	for scope, entries := range r {
		if len(entries) > metadataMaxEntries {
			return nil, fmt.Errorf("scope %q holds %d entries; the limit is %d", scope, len(entries), metadataMaxEntries)
		}
		for entry, values := range entries {
			for _, v := range values {
				buf, err := json.Marshal(v)
				if err != nil {
					return nil, err
				}
				if len(buf) > metadataMaxValueBytes {
					return nil, fmt.Errorf("a value of entry %q in scope %q is %d bytes; the limit is %d", entry, scope, len(buf), metadataMaxValueBytes)
				}
			}
		}
	}

	buf, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(buf) > metadataMaxBytes {
		return nil, fmt.Errorf("metadata is %d bytes; the limit is %d", len(buf), metadataMaxBytes)
	}
	return buf, nil
}

const pathKeysMetadataHelpSyn = `Read or change the metadata record of a named key`

const pathKeysMetadataHelpDesc = `
This path holds an opaque record beside a named key: scopes, each with
named entries, each entry a list of string values. Transit stores the
record but does not interpret it; it never changes how the key is used.

A write takes an ordered list of operations and applies them under the
key's lock, all or none, so concurrent writers never lose an update. The
record is limited to 64 KiB in total, 8 scopes, 128 entries per scope and
8 KiB per value. The record is deleted with the key and carried by backup
and restore.
`
