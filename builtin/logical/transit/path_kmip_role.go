// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const kmipRoleStoragePrefix = "kmip/roles/"

// kmipRole maps a client certificate Subject DN to a set of allowed KMIP
// operations and key names.
type kmipRole struct {
	CertSubjectDN     string   `json:"cert_subject_dn"`
	AllowedOperations []string `json:"allowed_operations"`
	AllowedKeyNames   []string `json:"allowed_key_names"`
}

func (b *backend) pathKmipRole() *framework.Path {
	return &framework.Path{
		Pattern: "kmip/roles/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "kmip-role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the KMIP role.",
			},
			"cert_subject_dn": {
				Type:        framework.TypeString,
				Description: "Distinguished Name (DN) of the client certificate subject that maps to this role.",
			},
			"allowed_operations": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of KMIP operations this role is permitted to perform (e.g. Create, Get, Locate, Destroy).",
			},
			"allowed_key_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of transit key names this role may access. Empty means all keys are allowed.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleRead,
				Summary:  "Read a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "kmip-role",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleWrite,
				Summary:  "Create or update a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "write",
					OperationSuffix: "kmip-role",
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleWrite,
				Summary:  "Create or update a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "create",
					OperationSuffix: "kmip-role",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleDelete,
				Summary:  "Delete a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "delete",
					OperationSuffix: "kmip-role",
				},
			},
		},

		HelpSynopsis:    pathKmipRoleHelpSyn,
		HelpDescription: pathKmipRoleHelpDesc,
	}
}

func (b *backend) pathKmipRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "kmip/roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "kmip-roles",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleListAll,
				Summary:  "List all KMIP roles.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "list",
					OperationSuffix: "kmip-roles",
				},
			},
		},

		HelpSynopsis:    pathKmipRoleListHelpSyn,
		HelpDescription: pathKmipRoleListHelpDesc,
	}
}

func (b *backend) pathKmipRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getKmipRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cert_subject_dn":    role.CertSubjectDN,
			"allowed_operations": role.AllowedOperations,
			"allowed_key_names":  role.AllowedKeyNames,
		},
	}, nil
}

func (b *backend) pathKmipRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Load existing role to allow partial updates
	role, err := b.getKmipRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &kmipRole{}
	}

	if v, ok := d.GetOk("cert_subject_dn"); ok {
		role.CertSubjectDN = v.(string)
	}
	if v, ok := d.GetOk("allowed_operations"); ok {
		role.AllowedOperations = v.([]string)
	}
	if v, ok := d.GetOk("allowed_key_names"); ok {
		role.AllowedKeyNames = v.([]string)
	}

	if err := b.putKmipRole(ctx, req.Storage, name, role); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathKmipRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := req.Storage.Delete(ctx, kmipRoleStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("error deleting KMIP role %q: %w", name, err)
	}

	return nil, nil
}

func (b *backend) pathKmipRoleListAll(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, kmipRoleStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("error listing KMIP roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) getKmipRole(ctx context.Context, s logical.Storage, name string) (*kmipRole, error) {
	entry, err := s.Get(ctx, kmipRoleStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("error reading KMIP role %q: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	var role kmipRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding KMIP role %q: %w", name, err)
	}
	return &role, nil
}

func (b *backend) putKmipRole(ctx context.Context, s logical.Storage, name string, role *kmipRole) error {
	entry, err := logical.StorageEntryJSON(kmipRoleStoragePrefix+name, role)
	if err != nil {
		return fmt.Errorf("error encoding KMIP role %q: %w", name, err)
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error storing KMIP role %q: %w", name, err)
	}
	return nil
}

const pathKmipRoleHelpSyn = `Manage KMIP roles that map client certificate Subject DNs to allowed operations`

const pathKmipRoleHelpDesc = `
A KMIP role maps a client certificate Subject Distinguished Name (DN) to a set
of allowed KMIP operations and transit key names. When a KMIP client connects
with mTLS, the transit KMIP server uses the client certificate's Subject DN to
look up the corresponding role and authorize or reject the requested operation.
`

const pathKmipRoleListHelpSyn = `List all configured KMIP roles`

const pathKmipRoleListHelpDesc = `
List all KMIP roles configured for this transit mount.
`
