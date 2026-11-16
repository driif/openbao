// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"net/http"
	"slices"
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
)

// Query advertises every route, and DiscoverVersions, which kmip-go's router
// answers without a route.
func TestSupportedOperations(t *testing.T) {
	require.NotContains(t, routes(), kmiplib.OperationDiscoverVersions)

	ops := supportedOperations()
	require.Len(t, ops, len(routes())+1)
	require.Contains(t, ops, kmiplib.OperationDiscoverVersions)
	require.True(t, slices.IsSorted(ops))
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

// KMIP 1.4 requires an answer to Query RNGs: Unspecified when the server
// cannot give details.
func TestHandleQuery_RNGs(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	resp, err := handleQuery(ctx, &payloads.QueryRequestPayload{QueryFunction: []kmiplib.QueryFunction{kmiplib.QueryFunctionRNGs}})
	require.NoError(t, err)
	require.Equal(t, []kmiplib.RNGParameters{{RNGAlgorithm: kmiplib.RNGAlgorithmUnspecified}}, resp.RNGParameters)
	require.Empty(t, resp.Operations)
}

// runBatch sends payloads as one request message through the package's
// routes and returns the response items.
func runBatch(t *testing.T, ctx context.Context, items ...kmiplib.OperationPayload) []kmiplib.ResponseBatchItem {
	t.Helper()
	exec := kmipserver.NewBatchExecutor()
	for op, h := range routes() {
		exec.Route(op, h)
	}
	msg := kmiplib.NewRequestMessage(kmiplib.V1_4, items...)
	resp := exec.HandleRequest(ctx, &msg)
	require.Len(t, resp.BatchItem, len(items))
	return resp.BatchItem
}

func locateBatch(t *testing.T, ctx context.Context, req *payloads.LocateRequestPayload) *payloads.LocateResponsePayload {
	t.Helper()
	item := runBatch(t, ctx, req)[0]
	require.NoError(t, item.Err())
	return item.ResponsePayload.(*payloads.LocateResponsePayload)
}

// A Locate with no attribute returns every key the client may read that is
// not soft-deleted, and pages them with Offset Items and Maximum Items. A
// revoked or destroyed object is returned only when the request names its
// State.
func TestHandleLocate_OmitsRevokedAndDestroyed(t *testing.T) {
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

	resp := locateBatch(t, ctx, &payloads.LocateRequestPayload{})
	require.Equal(t, []string{"app-a", "app-d", "app-e"}, resp.UniqueIdentifier)
	require.Equal(t, int32(3), *resp.LocatedItems)

	resp = locateBatch(t, ctx, &payloads.LocateRequestPayload{OffsetItems: 1, MaximumItems: 1})
	require.Equal(t, []string{"app-d"}, resp.UniqueIdentifier)
	require.Equal(t, int32(3), *resp.LocatedItems)

	resp = locateBatch(t, ctx, &payloads.LocateRequestPayload{OffsetItems: 2, MaximumItems: 3})
	require.Equal(t, []string{"app-e"}, resp.UniqueIdentifier)
	require.Equal(t, int32(3), *resp.LocatedItems)

	for state, want := range map[kmiplib.State][]string{
		kmiplib.StateDeactivated: {"app-b"},
		kmiplib.StateDestroyed:   {"app-c"},
	} {
		resp = locateBatch(t, ctx, &payloads.LocateRequestPayload{
			Attribute: []kmiplib.Attribute{{AttributeName: kmiplib.AttributeNameState, AttributeValue: state}},
		})
		require.Equal(t, want, resp.UniqueIdentifier, ttlv.EnumStr(state))
	}

	// An exact Name or Unique Identifier does not bring a revoked object back.
	for _, attr := range []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-b", NameType: kmiplib.NameTypeUninterpretedTextString}},
		{AttributeName: kmiplib.AttributeNameUniqueIdentifier, AttributeValue: "app-b"},
	} {
		resp = locateBatch(t, ctx, &payloads.LocateRequestPayload{Attribute: []kmiplib.Attribute{attr}})
		require.Empty(t, resp.UniqueIdentifier, attr.AttributeName)
	}
}

// No object is in archival storage, so a Storage Status Mask without On-line
// Storage matches nothing and sends no request.
func TestHandleLocate_StorageStatusMask(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("app-a")

	start := len(bao.all())
	resp := locateBatch(t, ctx, &payloads.LocateRequestPayload{StorageStatusMask: kmiplib.StorageStatusArchivalStorage})
	require.Empty(t, resp.UniqueIdentifier)
	require.Equal(t, int32(0), *resp.LocatedItems)
	require.Empty(t, since(bao, start))

	resp = locateBatch(t, ctx, &payloads.LocateRequestPayload{
		StorageStatusMask: kmiplib.StorageStatusOnlineStorage | kmiplib.StorageStatusArchivalStorage,
	})
	require.Equal(t, []string{"app-a"}, resp.UniqueIdentifier)
}

// Create, Register, and a Locate with one match make their object the ID
// Placeholder. A Locate with any other count empties it, so a batched item
// that names no Unique Identifier fails.
func TestHandlers_SetIDPlaceholder(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	uidOnly := &payloads.GetAttributesRequestPayload{AttributeName: []kmiplib.AttributeName{kmiplib.AttributeNameUniqueIdentifier}}
	aes := func(name string) kmiplib.TemplateAttribute {
		return *templateOf(
			kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: kmiplib.CryptographicAlgorithmAES},
			kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(256)},
			kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: name, NameType: kmiplib.NameTypeUninterpretedTextString}},
		)
	}

	items := runBatch(t, ctx,
		&payloads.CreateRequestPayload{ObjectType: kmiplib.ObjectTypeSymmetricKey, TemplateAttribute: aes("app-new")},
		uidOnly,
	)
	require.NoError(t, items[0].Err())
	require.NoError(t, items[1].Err())
	require.Equal(t, "app-new", items[1].ResponsePayload.(*payloads.GetAttributesResponsePayload).UniqueIdentifier)

	material := make([]byte, 32)
	items = runBatch(t, ctx,
		&payloads.RegisterRequestPayload{
			ObjectType:        kmiplib.ObjectTypeSymmetricKey,
			TemplateAttribute: aes("app-reg"),
			Object:            kmipObject(kmiplib.ObjectTypeSymmetricKey, kmiplib.CryptographicAlgorithmAES, 256, material),
		},
		uidOnly,
	)
	require.NoError(t, items[0].Err())
	require.NoError(t, items[1].Err())
	require.Equal(t, "app-reg", items[1].ResponsePayload.(*payloads.GetAttributesResponsePayload).UniqueIdentifier)

	m.createKey("app-other")
	byName := &payloads.LocateRequestPayload{Attribute: []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-other", NameType: kmiplib.NameTypeUninterpretedTextString}},
	}}
	items = runBatch(t, ctx, byName, uidOnly)
	require.NoError(t, items[1].Err())
	require.Equal(t, "app-other", items[1].ResponsePayload.(*payloads.GetAttributesResponsePayload).UniqueIdentifier)

	// The Create sets the ID Placeholder; the Locate with several matches
	// empties it again.
	items = runBatch(t, ctx,
		&payloads.CreateRequestPayload{ObjectType: kmiplib.ObjectTypeSymmetricKey, TemplateAttribute: aes("app-last")},
		&payloads.LocateRequestPayload{},
		uidOnly,
	)
	require.NoError(t, items[0].Err())
	require.NoError(t, items[1].Err())
	require.ErrorContains(t, items[2].Err(), "ID Placeholder is empty")
}

// Get returns a key in one format, not wrapped and not compressed. It
// refuses a request for anything else, and does not answer it with clear
// material in another form.
func TestHandleGet_RefusesUnsupportedOptions(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("app-a")

	for name, tc := range map[string]struct {
		req    payloads.GetRequestPayload
		reason kmiplib.ResultReason
	}{
		"wrapping": {
			payloads.GetRequestPayload{KeyWrappingSpecification: &kmiplib.KeyWrappingSpecification{WrappingMethod: kmiplib.WrappingMethodEncrypt}},
			kmiplib.ResultReasonFeatureNotSupported,
		},
		"format": {
			payloads.GetRequestPayload{KeyFormatType: kmiplib.KeyFormatTypeTransparentSymmetricKey},
			kmiplib.ResultReasonKeyFormatTypeNotSupported,
		},
		"compression": {
			payloads.GetRequestPayload{KeyCompressionType: kmiplib.KeyCompressionTypeECPublicKeyTypeX9_62CompressedPrime},
			kmiplib.ResultReasonKeyCompressionTypeNotSupported,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc.req.UniqueIdentifier = "app-a"
			item := runBatch(t, ctx, &tc.req)[0]
			require.Error(t, item.Err())
			require.Equal(t, tc.reason, item.ResultReason)
			require.Nil(t, item.ResponsePayload)
		})
	}

	item := runBatch(t, ctx, &payloads.GetRequestPayload{UniqueIdentifier: "app-a", KeyFormatType: kmiplib.KeyFormatTypeRaw})[0]
	require.NoError(t, item.Err())
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
