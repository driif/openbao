// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/forwarding"
)

const (
	auditFailureMessage = "KMIP audit failed; the operation may have completed"
	sealedMessage       = "KMIP operation refused: the store is sealed"
	standbyMessage      = "KMIP operation refused: standby has no audit broker; connect to the active node"
)

var auditDataKeys = []string{
	"kmip_operation", "client_certificate_subject", "unique_identifier",
	"unique_identifiers", "transit_mount", "outcome", "result_reason",
	"result_message", "transit_request_ids",
}

type operationAuditor struct {
	auditor   Auditor
	namespace string
	metrics   *listenerMetrics
}

type (
	auditBatchKey   struct{}
	auditBatch      struct{ records []*operationRecord }
	operationRecord struct {
		item    *kmiplib.RequestBatchItem
		input   *logical.LogInput
		ctx     context.Context
		ids     *forwarding.RequestIDs
		started time.Time
		message string
	}
)

// message accounts for every item, including header refusals and items skipped
// by BatchExecutor after Stop. All request records must succeed before any item
// executes. Each record has its own request ID collector; the item
// middleware runs the handler with it.
func (a *operationAuditor) message(next kmipserver.Next, ctx context.Context, req *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
	empty := len(req.BatchItem) == 0
	if empty {
		copy := *req
		copy.BatchItem = []kmiplib.RequestBatchItem{{}}
		req = &copy
	}
	batch := &auditBatch{}
	var refused error
	for i := range req.BatchItem {
		r, err := a.newRecord(ctx, &req.BatchItem[i])
		batch.records = append(batch.records, r)
		if err == nil && a.auditor != nil {
			err = a.auditor.AuditRequest(ctx, a.namespace, r.input)
		}
		if err != nil && (!errors.Is(err, consts.ErrStandby) || !discovery(r.item.Operation)) {
			refused = err
		}
	}
	var resp *kmiplib.ResponseMessage
	if empty {
		resp = failedMessage(req, kmiplib.ResultReasonInvalidMessage, safeResultMessage(kmiplib.ResultReasonInvalidMessage))
	} else if refused != nil {
		resp = failedMessage(req, kmiplib.ResultReasonGeneralFailure, auditRefusal(refused))
	} else {
		var err error
		resp, err = next(context.WithValue(ctx, auditBatchKey{}, batch), req)
		if err != nil {
			reason := kmiplib.ResultReasonGeneralFailure
			if e, ok := errors.AsType[kmipserver.Error](err); ok {
				reason = e.Reason
			}
			resp = failedMessage(req, reason, safeResultMessage(reason))
		}
	}
	if resp == nil {
		resp = failedMessage(req, kmiplib.ResultReasonGeneralFailure, safeResultMessage(kmiplib.ResultReasonGeneralFailure))
	}
	claimed := make(map[int]bool, len(batch.records))
	for i, r := range batch.records {
		bi := responseItem(resp, r.item, i, claimed)
		sanitizeResult(bi, r.message)
		// A core-state refusal has a fixed, actionable message instead of the
		// general failure text. Never copy decoder or backend errors here.
		if refused != nil {
			bi.ResultMessage = auditRefusal(refused)
		}
		input := a.responseInput(ctx, r, bi)
		if a.auditor != nil {
			err := a.auditor.AuditResponse(ctx, a.namespace, input)
			if err != nil && (!errors.Is(err, consts.ErrStandby) || !discovery(r.item.Operation)) {
				failItem(bi, kmiplib.ResultReasonGeneralFailure, auditRefusal(err))
			}
		}
		outcome := "success"
		if bi.ResultStatus != kmiplib.ResultStatusSuccess {
			outcome = reasonName(bi.ResultReason)
		}
		errorReason := outcome
		if bi.ResultMessage == sealedMessage {
			errorReason = "sealed"
		}
		a.metrics.operation(operationName(r.item.Operation), outcome, errorReason, r.started)
	}
	return resp, nil
}

func (a *operationAuditor) item(next kmipserver.BatchItemNext, ctx context.Context, item *kmiplib.RequestBatchItem) (*kmiplib.ResponseBatchItem, error) {
	if batch, ok := ctx.Value(auditBatchKey{}).(*auditBatch); ok {
		for _, r := range batch.records {
			if r.item == item {
				resp, err := next(r.ctx, item)
				if e, ok := errors.AsType[operationError](err); ok {
					r.message = e.Error()
				}
				return resp, err
			}
		}
	}
	return next(ctx, item)
}

func (a *operationAuditor) newRecord(ctx context.Context, item *kmiplib.RequestBatchItem) (*operationRecord, error) {
	id, err := uuid.GenerateUUID()
	data := map[string]any{"kmip_operation": operationName(item.Operation)}
	req := &logical.Request{ID: id, Operation: logical.UpdateOperation, Path: "kmip/" + operationName(item.Operation), MountType: "transit", Data: data}
	switch item.Operation {
	case kmiplib.OperationGet, kmiplib.OperationGetAttributes, kmiplib.OperationGetAttributeList, kmiplib.OperationLocate, kmiplib.OperationQuery, kmiplib.OperationDiscoverVersions:
		req.Operation = logical.ReadOperation
	}
	in := &logical.LogInput{Type: "request", Request: req, NonHMACReqDataKeys: auditDataKeys, NonHMACRespDataKeys: auditDataKeys}
	sessionMetadata(ctx, in, data)
	addIdentifiers(data, item.RequestPayload)
	collectorCtx, ids := forwarding.WithRequestIDs(ctx)
	return &operationRecord{item: item, input: in, ctx: collectorCtx, ids: ids, started: time.Now()}, err
}

func sessionMetadata(ctx context.Context, in *logical.LogInput, data map[string]any) {
	s, _ := ctx.Value(sessionKey{}).(*session)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in.Auth = s.auth // immutable and contains no token
	if s.mount != "" {
		in.Request.MountPoint = s.mount + "/"
		in.Request.Path = s.mount + "/kmip/" + data["kmip_operation"].(string)
		data["transit_mount"] = s.mount
	}
	host, port, _ := net.SplitHostPort(s.remoteAddr)
	portNumber, _ := strconv.Atoi(port)
	in.Request.Connection = &logical.Connection{RemoteAddr: host, RemotePort: portNumber}
	if len(s.peerCerts) > 0 {
		in.Request.Connection.ConnState = s.connectionState
		if in.Request.Connection.ConnState == nil {
			in.Request.Connection.ConnState = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: s.peerCerts}
		}
		data["client_certificate_subject"] = s.peerCerts[0].Subject.String()
	}
}

func (a *operationAuditor) responseInput(ctx context.Context, r *operationRecord, bi *kmiplib.ResponseBatchItem) *logical.LogInput {
	in := *r.input
	req := *in.Request
	req.Data = maps.Clone(req.Data)
	in.Request, in.Type = &req, "response"
	data := maps.Clone(req.Data)
	sessionMetadata(ctx, &in, data)
	addIdentifiers(data, bi.ResponsePayload)
	data["outcome"] = "success"
	data["result_reason"] = ""
	data["result_message"] = bi.ResultMessage
	data["transit_request_ids"] = r.ids.Values()
	if bi.ResultStatus != kmiplib.ResultStatusSuccess {
		data["outcome"] = reasonName(bi.ResultReason)
		data["result_reason"] = reasonName(bi.ResultReason)
		message := safeResultMessage(bi.ResultReason)
		if bi.ResultMessage == sealedMessage || bi.ResultMessage == standbyMessage || bi.ResultMessage == auditFailureMessage {
			message = bi.ResultMessage
		}
		data["result_message"] = message
		in.OuterErr = errors.New(message)
	}
	in.Response = &logical.Response{Data: data}
	return &in
}

// addIdentifiers reads only explicit identifier fields, and the Unique
// Identifier attribute of a Locate filter. In particular it never walks
// templates, other attributes, Names, objects or cryptographic payloads.
func addIdentifiers(data map[string]any, payload kmiplib.OperationPayload) {
	v := reflect.ValueOf(payload)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return
	}
	var ids []string
	for _, name := range []string{"UniqueIdentifier", "PrivateKeyUniqueIdentifier", "PublicKeyUniqueIdentifier"} {
		f := v.FieldByName(name)
		if !f.IsValid() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			if id := f.String(); id != "" {
				ids = append(ids, id)
			}
		case reflect.Slice:
			if values, ok := reflect.TypeAssert[[]string](f); ok {
				ids = append(ids, values...)
			}
		}
	}
	if locate, ok := payload.(*payloads.LocateRequestPayload); ok {
		for _, attr := range locate.Attribute {
			if id, ok := attr.AttributeValue.(string); ok && attr.AttributeName == kmiplib.AttributeNameUniqueIdentifier && id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 1 {
		data["unique_identifier"] = ids[0]
	}
	if len(ids) > 1 {
		data["unique_identifiers"] = slices.Clone(ids)
	}
}

func discovery(op kmiplib.Operation) bool {
	return op == kmiplib.OperationQuery || op == kmiplib.OperationDiscoverVersions
}

func operationName(op kmiplib.Operation) string {
	name := ttlv.EnumStr(op)
	if name == "" || strings.HasPrefix(name, "0x") {
		return "Unknown"
	}
	return name
}

func reasonName(reason kmiplib.ResultReason) string {
	name := ttlv.EnumStr(reason)
	if name == "" || strings.HasPrefix(name, "0x") {
		return "GeneralFailure"
	}
	return name
}

func safeResultMessage(reason kmiplib.ResultReason) string {
	return "KMIP operation failed: " + reasonName(reason)
}

func sanitizeResult(bi *kmiplib.ResponseBatchItem, message string) {
	if bi.ResultStatus != kmiplib.ResultStatusSuccess {
		bi.ResultMessage = message
		if message == "" {
			bi.ResultMessage = safeResultMessage(bi.ResultReason)
		}
		bi.ResponsePayload = nil
	} else {
		bi.ResultMessage = ""
	}
}

func auditRefusal(err error) string {
	switch {
	case errors.Is(err, consts.ErrSealed):
		return sealedMessage
	case errors.Is(err, consts.ErrStandby):
		return standbyMessage
	default:
		return auditFailureMessage
	}
}

func failItem(bi *kmiplib.ResponseBatchItem, reason kmiplib.ResultReason, message string) {
	bi.ResultStatus, bi.ResultReason, bi.ResultMessage = kmiplib.ResultStatusOperationFailed, reason, message
	bi.ResponsePayload = nil
}

func failedMessage(req *kmiplib.RequestMessage, reason kmiplib.ResultReason, message string) *kmiplib.ResponseMessage {
	resp := &kmiplib.ResponseMessage{Header: kmiplib.ResponseHeader{ProtocolVersion: req.Header.ProtocolVersion, TimeStamp: time.Now(), BatchCount: int32(len(req.BatchItem))}, BatchItem: make([]kmiplib.ResponseBatchItem, len(req.BatchItem))}
	for i, item := range req.BatchItem {
		bi := &resp.BatchItem[i]
		bi.Operation, bi.UniqueBatchItemID = item.Operation, item.UniqueBatchItemID
		failItem(bi, reason, message)
	}
	return resp
}

// responseItem returns the response item for a request item and claims it, so
// two request items never share one response item, even with the same Unique
// Batch Item ID. An item with an ID matches by ID; one without matches by
// position. An item with no match gets a failed item appended for it.
func responseItem(resp *kmiplib.ResponseMessage, item *kmiplib.RequestBatchItem, index int, claimed map[int]bool) *kmiplib.ResponseBatchItem {
	pick := -1
	if len(item.UniqueBatchItemID) > 0 {
		for i := range resp.BatchItem {
			if !claimed[i] && slices.Equal(item.UniqueBatchItemID, resp.BatchItem[i].UniqueBatchItemID) {
				pick = i
				break
			}
		}
	} else if index < len(resp.BatchItem) && !claimed[index] {
		pick = index
	}
	if pick < 0 {
		missing := kmiplib.ResponseBatchItem{Operation: item.Operation, UniqueBatchItemID: item.UniqueBatchItemID}
		failItem(&missing, kmiplib.ResultReasonOperationCanceledByRequester, safeResultMessage(kmiplib.ResultReasonOperationCanceledByRequester))
		resp.BatchItem = append(resp.BatchItem, missing)
		resp.Header.BatchCount = int32(len(resp.BatchItem))
		pick = len(resp.BatchItem) - 1
	}
	claimed[pick] = true
	return &resp.BatchItem[pick]
}
