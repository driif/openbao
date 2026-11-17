// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/corehelpers"
	"github.com/stretchr/testify/require"
)

func TestKMIPAuditCoreState(t *testing.T) {
	core := TestCore(t)
	in := &logical.LogInput{Request: &logical.Request{ID: "kmip-audit", Path: "kmip/Query", Operation: logical.ReadOperation}, Response: &logical.Response{}}
	require.ErrorIs(t, core.AuditRequest(t.Context(), "", in), consts.ErrSealed)
	require.ErrorIs(t, core.AuditResponse(t.Context(), "", in), consts.ErrSealed)

	core, _, _ = TestCoreUnsealed(t)
	t.Cleanup(func() { _ = core.Shutdown() })
	device := corehelpers.TestNoopAudit(t, nil)
	core.auditBroker.Register("kmip-test", device, nil, false)
	ctx := namespace.RootContext(t.Context())
	require.NoError(t, core.AuditRequest(ctx, "", in))
	require.NoError(t, core.AuditResponse(ctx, "", in))
	require.Len(t, device.Req, 1)
	require.Len(t, device.Resp, 1)
	require.Equal(t, "kmip-audit", device.Req[0].ID)
	require.Error(t, core.AuditRequest(ctx, "missing", in))
	device.ReqErr = errors.New("device unavailable")
	device.RespErr = errors.New("device unavailable")
	require.Error(t, core.AuditRequest(ctx, "", in))
	require.Error(t, core.AuditResponse(ctx, "", in))
	// No broker reference is cached between calls, including on a standby.
	core.stateLock.Lock()
	broker := core.auditBroker
	core.auditBroker = nil
	core.standby.Store(true)
	core.stateLock.Unlock()
	require.ErrorIs(t, core.AuditRequest(ctx, "", in), consts.ErrStandby)
	require.ErrorIs(t, core.AuditResponse(ctx, "", in), consts.ErrStandby)
	core.stateLock.Lock()
	core.auditBroker = broker
	core.standby.Store(false)
	core.stateLock.Unlock()
	device.ReqErr = nil
	require.NoError(t, core.AuditRequest(ctx, "", in))
}
