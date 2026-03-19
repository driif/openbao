// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"
	"slices"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// ctxKmipRole is the context key used to store the authenticated kmipRole.
type ctxKmipRole struct{}

// kmipRoleFromContext retrieves the kmipRole stored in ctx by authMiddleware.
// Returns nil if no role is present.
func kmipRoleFromContext(ctx context.Context) *kmipRole {
	v, _ := ctx.Value(ctxKmipRole{}).(*kmipRole)
	return v
}

// authMiddleware returns a kmipserver.Middleware that authenticates KMIP
// connections by matching the TLS client certificate Subject DN against
// configured kmipRoles. The matched role is stored in the request context
// for downstream authorizeOperation checks.
//
// If RequireClientCert is false on the KMIP config, the server may not supply
// peer certificates; in that case the middleware stores a nil role and allows
// the request to proceed (authorization is still enforced per-operation).
//
// If RequireClientCert is true (the default) and no matching role is found,
// the middleware returns PermissionDenied.
func authMiddleware(b *backend) kmipserver.Middleware {
	return func(next kmipserver.Next, ctx context.Context, msg *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
		certs := kmipserver.PeerCertificates(ctx)

		if len(certs) == 0 {
			// No client cert present. When RequireClientCert is false the TLS
			// layer uses tls.NoClientCert, so unauthenticated connections reach
			// here. Inject a permissive wildcard role (empty AllowedOperations
			// and empty AllowedKeyNames = all operations on all keys allowed)
			// so that authorizeOperation checks pass for these connections.
			// When RequireClientCert is true the TLS handshake would have
			// rejected the connection before we get here.
			ctx = context.WithValue(ctx, ctxKmipRole{}, &kmipRole{})
			return next(ctx, msg)
		}

		subjectDN := certs[0].Subject.String()

		role, err := b.findKmipRoleByDN(ctx, subjectDN)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "auth: failed to look up role: %s", err)
		}
		if role == nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "auth: no role found for subject DN %q", subjectDN)
		}

		ctx = context.WithValue(ctx, ctxKmipRole{}, role)
		return next(ctx, msg)
	}
}

// findKmipRoleByDN iterates all stored kmipRoles and returns the first whose
// CertSubjectDN matches dn. Returns (nil, nil) when no match is found.
func (b *backend) findKmipRoleByDN(ctx context.Context, dn string) (*kmipRole, error) { //nolint:nilnil
	if b.storage == nil {
		return nil, nil //nolint:nilnil
	}

	names, err := b.storage.List(ctx, kmipRoleStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("listing kmip roles: %w", err)
	}

	for _, name := range names {
		role, err := b.getKmipRole(ctx, b.storage, name)
		if err != nil {
			return nil, err
		}
		if role != nil && role.CertSubjectDN == dn {
			return role, nil
		}
	}
	return nil, nil //nolint:nilnil
}

// authorizeOperation checks whether the role stored in ctx allows the given
// KMIP operation on the given keyName.
//
//   - If no role is in ctx, the operation is denied.
//   - If role.AllowedOperations is empty, all operations are permitted.
//   - If role.AllowedKeyNames is empty, all key names are permitted.
func authorizeOperation(ctx context.Context, op kmip.Operation, keyName string) error {
	role := kmipRoleFromContext(ctx)
	if role == nil {
		return kmipserver.ErrPermissionDenied
	}

	// Check operation allowlist (empty = all allowed).
	if len(role.AllowedOperations) > 0 {
		opStr := ttlv.EnumStr(op)
		if !slices.Contains(role.AllowedOperations, opStr) {
			return kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "operation %q is not allowed for this role", opStr)
		}
	}

	// Check key name allowlist (empty = all allowed).
	if keyName != "" && len(role.AllowedKeyNames) > 0 {
		if !slices.Contains(role.AllowedKeyNames, keyName) {
			return kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "key %q is not allowed for this role", keyName)
		}
	}

	return nil
}
