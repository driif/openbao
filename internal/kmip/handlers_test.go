// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"net/http"
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
)

func TestRoutesMatchSupportedOps(t *testing.T) {
	// kmip-go's router answers DiscoverVersions without a route.
	registered := map[kmiplib.Operation]bool{kmiplib.OperationDiscoverVersions: true}
	for op := range routes() {
		if registered[op] {
			t.Errorf("%s has a route, but the router answers it", ttlv.EnumStr(op))
		}
		registered[op] = true
	}

	if len(registered) != len(SupportedOperations) {
		t.Fatalf("count mismatch: supported=%d registered routes=%d", len(SupportedOperations), len(registered))
	}

	for _, op := range SupportedOperations {
		if !registered[op] {
			t.Errorf("%s is in SupportedOperations but has no route", ttlv.EnumStr(op))
		}
	}
}

func TestHandleQuery_ReportsAttributeOperations(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	resp, err := handleQuery(ctx, &payloads.QueryRequestPayload{QueryFunction: []kmiplib.QueryFunction{kmiplib.QueryFunctionOperations}})
	require.NoError(t, err)
	require.Contains(t, resp.Operations, kmiplib.OperationModifyAttribute)
	require.Contains(t, resp.Operations, kmiplib.OperationDeleteAttribute)
	require.Empty(t, bao.all())
}

// A Locate with no attribute returns every key the client may read, in every
// State, and pages them with Offset Items and Maximum Items.
func TestHandleLocate_NoAttributeReturnsEveryReadableKey(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	for _, uid := range []string{"app-a", "app-b", "app-c", "app-d", "denied"} {
		m.createKey(uid)
	}
	bao.route(http.MethodGet, "transit/keys/denied", respond(http.StatusForbidden, withErrors("permission denied")))
	require.NoError(t, op(t, ctx).revoke(ctx, "app-b", unspecified, nil))
	require.NoError(t, op(t, ctx).revoke(ctx, "app-c", unspecified, nil))
	require.NoError(t, op(t, ctx).destroy(ctx, "app-c"))
	newPreActive(t, ctx, "app-e")

	resp, err := handleLocate(ctx, &payloads.LocateRequestPayload{})
	require.NoError(t, err)
	require.Equal(t, []string{"app-a", "app-b", "app-c", "app-d", "app-e"}, resp.UniqueIdentifier)
	require.Equal(t, int32(5), *resp.LocatedItems)

	resp, err = handleLocate(ctx, &payloads.LocateRequestPayload{OffsetItems: 1, MaximumItems: 3})
	require.NoError(t, err)
	require.Equal(t, []string{"app-b", "app-c", "app-d"}, resp.UniqueIdentifier)
	require.Equal(t, int32(5), *resp.LocatedItems)

	resp, err = handleLocate(ctx, &payloads.LocateRequestPayload{OffsetItems: 4, MaximumItems: 3})
	require.NoError(t, err)
	require.Equal(t, []string{"app-e"}, resp.UniqueIdentifier)
	require.Equal(t, int32(5), *resp.LocatedItems)
}

// ModifyAttribute and DeleteAttribute answer with the Attribute Index of the
// instance they changed. KMIP lets a response omit it only when it is 0.
func TestHandleModifyDeleteAttribute_ReturnIndex(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newTaggedKey(t, ctx, "blue", "green")

	exec := kmipserver.NewBatchExecutor()
	for op, h := range routes() {
		exec.Route(op, h)
	}
	one := int32(1)
	msg := kmiplib.NewRequestMessage(
		kmiplib.V1_4,
		&payloads.ModifyAttributeRequestPayload{UniqueIdentifier: "app-a", Attribute: indexed(customAttr("x-tag", "red"), 1)},
		&payloads.ModifyAttributeRequestPayload{UniqueIdentifier: "app-a", Attribute: customAttr("x-tag", "cyan")},
		&payloads.DeleteAttributeRequestPayload{UniqueIdentifier: "app-a", AttributeName: "x-tag", AttributeIndex: &one},
		&payloads.DeleteAttributeRequestPayload{UniqueIdentifier: "app-a", AttributeName: kmiplib.AttributeNameDestroyDate},
	)
	resp := exec.HandleRequest(ctx, &msg)
	require.Len(t, resp.BatchItem, 4)
	for _, item := range resp.BatchItem[:3] {
		require.NoError(t, item.Err())
	}

	modified := resp.BatchItem[0].ResponsePayload.(*payloads.ModifyAttributeResponsePayload)
	require.Equal(t, "app-a", modified.UniqueIdentifier)
	require.Equal(t, int32(1), *modified.Attribute.AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "red"), modified.Attribute))
	require.Nil(t, resp.BatchItem[1].ResponsePayload.(*payloads.ModifyAttributeResponsePayload).Attribute.AttributeIndex)

	deleted := resp.BatchItem[2].ResponsePayload.(*payloads.DeleteAttributeResponsePayload)
	require.Equal(t, int32(1), *deleted.Attribute.AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "red"), deleted.Attribute))
	requireTags(t, ctx, "cyan")

	require.ErrorContains(t, resp.BatchItem[3].Err(), "attribute Destroy Date is set by the server and cannot be deleted")
}
