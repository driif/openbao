// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/stretchr/testify/require"
)

func TestAuditEmptyBatch(t *testing.T) {
	a := &operationAuditor{metrics: &listenerMetrics{sink: metricsutil.BlackholeSink()}}
	exec := kmipserver.NewBatchExecutor()
	exec.Use(a.message)
	resp := exec.HandleRequest(t.Context(), &kmiplib.RequestMessage{Header: kmiplib.RequestHeader{ProtocolVersion: kmiplib.V1_4}})
	require.Len(t, resp.BatchItem, 1)
	require.Equal(t, kmiplib.ResultReasonInvalidMessage, resp.BatchItem[0].ResultReason)
}

func TestAuditShortResponse(t *testing.T) {
	a := &operationAuditor{metrics: &listenerMetrics{sink: metricsutil.BlackholeSink()}}
	req := &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationQuery}}}
	resp, err := a.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		return &kmiplib.ResponseMessage{}, nil
	}, t.Context(), req)
	require.NoError(t, err)
	require.Len(t, resp.BatchItem, 1)
	require.Equal(t, kmiplib.ResultStatusOperationFailed, resp.BatchItem[0].ResultStatus)
}

type recordingAuditor struct {
	mu                      sync.Mutex
	requests, responses     []*logical.LogInput
	requestErr, responseErr error
}

func (a *recordingAuditor) AuditRequest(_ context.Context, _ string, in *logical.LogInput) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, in)
	return a.requestErr
}

func (a *recordingAuditor) AuditResponse(_ context.Context, _ string, in *logical.LogInput) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.responses = append(a.responses, in)
	return a.responseErr
}

func TestAuditFailures(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		requestErr, responseErr error
		op                      kmiplib.Operation
		executes                bool
		message                 string
	}{
		{name: "request", requestErr: errors.New("secret device error"), op: kmiplib.OperationCreate, message: auditFailureMessage},
		{name: "response", responseErr: errors.New("secret device error"), op: kmiplib.OperationCreate, executes: true, message: auditFailureMessage},
		{name: "sealed", requestErr: consts.ErrSealed, op: kmiplib.OperationQuery, message: sealedMessage},
		{name: "standby write", requestErr: consts.ErrStandby, op: kmiplib.OperationCreate, message: standbyMessage},
		{name: "standby query", requestErr: consts.ErrStandby, responseErr: consts.ErrStandby, op: kmiplib.OperationQuery, executes: true},
		{name: "standby discover", requestErr: consts.ErrStandby, responseErr: consts.ErrStandby, op: kmiplib.OperationDiscoverVersions, executes: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditor := &recordingAuditor{requestErr: tc.requestErr, responseErr: tc.responseErr}
			sink := metrics.NewInmemSink(time.Hour, time.Hour)
			a := &operationAuditor{auditor: auditor, metrics: &listenerMetrics{sink: metricsutil.NewClusterMetricSink("test", sink)}}
			executed := false
			resp, err := a.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
				executed = true
				return &kmiplib.ResponseMessage{BatchItem: []kmiplib.ResponseBatchItem{{Operation: tc.op}}}, nil
			}, t.Context(), &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{{Operation: tc.op}}})
			require.NoError(t, err)
			require.Equal(t, tc.executes, executed)
			require.Len(t, auditor.requests, 1)
			require.Len(t, auditor.responses, 1)
			require.Equal(t, auditor.requests[0].Request.ID, auditor.responses[0].Request.ID)
			require.Equal(t, tc.message, resp.BatchItem[0].ResultMessage)
			count := 0.0
			for _, interval := range sink.Data() {
				for _, c := range interval.Counters {
					if c.Name == "kmip.errors" {
						count += c.Sum
					}
				}
			}
			if tc.message != "" {
				require.Equal(t, 1.0, count)
			} else {
				require.Zero(t, count)
			}
		})
	}
}

func TestAuditBatchStopAndDiagnostics(t *testing.T) {
	auditor := new(recordingAuditor)
	a := &operationAuditor{auditor: auditor, metrics: &listenerMetrics{sink: metricsutil.BlackholeSink()}}
	exec := kmipserver.NewBatchExecutor()
	exec.Use(a.message)
	exec.BatchItemUse(a.item)
	exec.Route(kmiplib.OperationQuery, kmipserver.HandleFunc(func(context.Context, *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
		return nil, operationErrorf(kmiplib.ResultReasonPermissionDenied, "wrong key lifecycle state")
	}))
	req := &kmiplib.RequestMessage{Header: kmiplib.RequestHeader{ProtocolVersion: kmiplib.V1_4, BatchCount: 2, BatchErrorContinuationOption: kmiplib.BatchErrorContinuationOptionStop}, BatchItem: []kmiplib.RequestBatchItem{
		{Operation: kmiplib.OperationQuery, UniqueBatchItemID: []byte{1}, RequestPayload: &payloads.QueryRequestPayload{}},
		{Operation: kmiplib.OperationQuery, UniqueBatchItemID: []byte{2}, RequestPayload: &payloads.QueryRequestPayload{}},
	}}
	resp := exec.HandleRequest(t.Context(), req)
	require.Len(t, auditor.requests, 2)
	require.Len(t, auditor.responses, 2)
	require.Equal(t, "wrong key lifecycle state", resp.BatchItem[0].ResultMessage)
	require.Equal(t, kmiplib.ResultReasonOperationCanceledByRequester, resp.BatchItem[1].ResultReason)
	require.NotEqual(t, auditor.requests[0].Request.ID, auditor.requests[1].Request.ID)
	for i := range auditor.requests {
		require.Equal(t, auditor.requests[i].Request.ID, auditor.responses[i].Request.ID)
	}
}

func TestAuditPayloadExclusion(t *testing.T) {
	secret := []byte("unique-secret-material-32bytes!!!")
	auditor := new(recordingAuditor)
	sink := metrics.NewInmemSink(time.Hour, time.Hour)
	a := &operationAuditor{auditor: auditor, metrics: &listenerMetrics{sink: metricsutil.NewClusterMetricSink("test", sink)}}
	req := &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationEncrypt, RequestPayload: &payloads.EncryptRequestPayload{UniqueIdentifier: "object-secret-uid", Data: secret}}}}
	_, err := a.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		return &kmiplib.ResponseMessage{BatchItem: []kmiplib.ResponseBatchItem{{ResultStatus: kmiplib.ResultStatusOperationFailed, ResultReason: kmiplib.ResultReasonGeneralFailure, ResultMessage: string(secret)}}}, nil
	}, t.Context(), req)
	require.NoError(t, err)
	raw, err := json.Marshal(auditor.responses[0].Response.Data)
	require.NoError(t, err)
	for _, value := range []string{string(secret), base64.StdEncoding.EncodeToString(secret), hex.EncodeToString(secret)} {
		require.NotContains(t, string(raw), value)
	}
	require.Equal(t, "object-secret-uid", auditor.responses[0].Response.Data["unique_identifier"])
	for _, interval := range sink.Data() {
		for key := range interval.Counters {
			require.NotContains(t, key, "object-secret-uid")
		}
		for key := range interval.Samples {
			require.NotContains(t, key, "object-secret-uid")
		}
	}
}

func TestAuditLocateIdentifier(t *testing.T) {
	auditor := new(recordingAuditor)
	a := &operationAuditor{auditor: auditor, metrics: &listenerMetrics{sink: metricsutil.NewClusterMetricSink("test", metrics.NewInmemSink(time.Hour, time.Hour))}}
	req := &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationLocate, RequestPayload: &payloads.LocateRequestPayload{Attribute: []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "not-an-identifier", NameType: kmiplib.NameTypeUninterpretedTextString}},
		{AttributeName: kmiplib.AttributeNameUniqueIdentifier, AttributeValue: "app-located"},
	}}}}}
	_, err := a.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		return &kmiplib.ResponseMessage{BatchItem: []kmiplib.ResponseBatchItem{{Operation: kmiplib.OperationLocate, ResponsePayload: &payloads.LocateResponsePayload{}}}}, nil
	}, t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "app-located", auditor.requests[0].Request.Data["unique_identifier"])
	require.Equal(t, "app-located", auditor.responses[0].Response.Data["unique_identifier"])
}

func TestAuditMatchesBatchIDs(t *testing.T) {
	req := &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationQuery, UniqueBatchItemID: []byte{1}}, {Operation: kmiplib.OperationGet, UniqueBatchItemID: []byte{2}}}}
	resp := &kmiplib.ResponseMessage{BatchItem: []kmiplib.ResponseBatchItem{{Operation: kmiplib.OperationGet, UniqueBatchItemID: []byte{2}}, {Operation: kmiplib.OperationQuery, UniqueBatchItemID: []byte{1}}}}
	claimed := map[int]bool{}
	require.Same(t, &resp.BatchItem[1], responseItem(resp, &req.BatchItem[0], 0, claimed))
	require.Same(t, &resp.BatchItem[0], responseItem(resp, &req.BatchItem[1], 1, claimed))
}

// Two items with one Unique Batch Item ID are each audited, and a failed
// response audit fails both of them.
func TestAuditDuplicateBatchIDs(t *testing.T) {
	auditor := &recordingAuditor{responseErr: errors.New("audit device down")}
	a := &operationAuditor{auditor: auditor, metrics: &listenerMetrics{sink: metricsutil.BlackholeSink()}}
	id := []byte{7}
	req := &kmiplib.RequestMessage{BatchItem: []kmiplib.RequestBatchItem{
		{Operation: kmiplib.OperationGet, UniqueBatchItemID: id, RequestPayload: &payloads.GetRequestPayload{UniqueIdentifier: "app-a"}},
		{Operation: kmiplib.OperationGet, UniqueBatchItemID: id, RequestPayload: &payloads.GetRequestPayload{UniqueIdentifier: "app-b"}},
	}}
	resp, err := a.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		return &kmiplib.ResponseMessage{BatchItem: []kmiplib.ResponseBatchItem{
			{Operation: kmiplib.OperationGet, UniqueBatchItemID: id, ResponsePayload: &payloads.GetResponsePayload{UniqueIdentifier: "app-a"}},
			{Operation: kmiplib.OperationGet, UniqueBatchItemID: id, ResponsePayload: &payloads.GetResponsePayload{UniqueIdentifier: "app-b"}},
		}}, nil
	}, t.Context(), req)
	require.NoError(t, err)
	require.Len(t, resp.BatchItem, 2)
	for _, bi := range resp.BatchItem {
		require.Equal(t, kmiplib.ResultStatusOperationFailed, bi.ResultStatus)
		require.Nil(t, bi.ResponsePayload)
	}
	require.Len(t, auditor.responses, 2)
	require.Equal(t, "app-a", auditor.responses[0].Response.Data["unique_identifier"])
	require.Equal(t, "app-b", auditor.responses[1].Response.Data["unique_identifier"])
}

func TestAuditRejectsUntrustedErrors(t *testing.T) {
	secret := "backend-secret-payload"
	require.NotContains(t, mapError(errors.New(secret)).Error(), secret)
	require.NotContains(t, clientErrorText(errors.New(secret)), secret)
	reply := &reply{status: 500, Errors: []string{secret}}
	require.NotContains(t, reply.failure().Error(), secret)
	reply.Data = json.RawMessage(`{"value":"` + secret + `"}`)
	var data struct{ Value int }
	require.NotContains(t, reply.decode(&data).Error(), secret)
}
