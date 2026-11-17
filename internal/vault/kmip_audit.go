// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
)

// AuditRequest logs a KMIP operation through the configured audit devices.
// The lock protects only this broker call. It must not span execution of the
// operation, which enters HandleRequest and takes the same read lock.
func (c *Core) AuditRequest(ctx context.Context, nsPath string, in *logical.LogInput) error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	ctx, err := c.kmipAuditContext(ctx, nsPath)
	if err != nil {
		return err
	}
	return c.auditBroker.LogRequest(ctx, in, c.auditedHeaders)
}

// AuditResponse logs a KMIP result, resolving the current broker again after
// execution. No broker reference survives a core state transition.
func (c *Core) AuditResponse(ctx context.Context, nsPath string, in *logical.LogInput) error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	ctx, err := c.kmipAuditContext(ctx, nsPath)
	if err != nil {
		return err
	}
	return c.auditBroker.LogResponse(ctx, in, c.auditedHeaders)
}

// kmipAuditContext requires stateLock to be held.
func (c *Core) kmipAuditContext(ctx context.Context, nsPath string) (context.Context, error) {
	if c.Sealed() {
		return nil, consts.ErrSealed
	}
	if c.auditBroker == nil {
		if c.standby.Load() {
			return nil, consts.ErrStandby
		}
		return nil, errors.New("KMIP audit broker is unavailable")
	}
	ctx = namespace.RootContext(ctx)
	ns, err := c.namespaceStore.GetNamespaceByPath(ctx, nsPath)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, errors.New("KMIP audit namespace is unavailable")
	}
	return namespace.ContextWithNamespace(ctx, ns), nil
}
