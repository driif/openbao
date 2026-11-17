// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"errors"
	"fmt"
	"net/http"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// operationError marks diagnostics authored by this package. The audit record
// uses fixed text per reason; only the client receives these diagnostics.
type operationError struct{ detail kmipserver.Error }

func (e operationError) Error() string { return e.detail.Error() }
func (e operationError) Unwrap() error { return e.detail }

func operationErrorf(reason kmiplib.ResultReason, format string, args ...any) error {
	return operationError{kmipserver.Error{Reason: reason, Message: fmt.Sprintf(format, args...)}}
}

func clientErrorText(err error) string {
	if e, ok := errors.AsType[operationError](err); ok {
		return e.Error()
	}
	return safeResultMessage(kmiplib.ResultReasonGeneralFailure)
}

// mapError returns err as a KMIP error. Errors the translator has already
// classified pass through; anything else is a General Failure.
func mapError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := errors.AsType[kmipserver.Error](err); ok {
		return err
	}

	return operationErrorf(kmiplib.ResultReasonGeneralFailure, "%s", safeResultMessage(kmiplib.ResultReasonGeneralFailure))
}

// failure turns an unsuccessful reply into a KMIP error. A 403 names the
// path and the capability the call needed, since that is what an operator
// has to grant.
func (r *reply) failure() error {
	switch r.status {
	case http.StatusForbidden:
		return operationErrorf(
			kmiplib.ResultReasonPermissionDenied,
			"permission denied: %s %s requires the %q capability", r.method, r.path, r.capability,
		)
	case http.StatusNotFound:
		return operationErrorf(kmiplib.ResultReasonItemNotFound, "%s not found", r.path)
	case http.StatusBadRequest:
		return operationErrorf(kmiplib.ResultReasonInvalidField, "%s %s: invalid request", r.method, r.path)
	default:
		return operationErrorf(kmiplib.ResultReasonGeneralFailure, "%s %s: status %d", r.method, r.path, r.status)
	}
}

func errNotFound(uid string) error {
	return operationErrorf(kmiplib.ResultReasonItemNotFound, "object %q not found", uid)
}

// errWrongState reports an operation that the object's State does not
// allow. KMIP 1.x, which kmip-go serves, has no Wrong Key Lifecycle State
// result reason (it arrived in KMIP 2.0), so this is Permission Denied with
// a message that names the state.
func errWrongState(uid string, state kmiplib.State) error {
	return operationErrorf(
		kmiplib.ResultReasonPermissionDenied,
		"wrong key lifecycle state: object %q is %s", uid, ttlv.EnumStr(state),
	)
}

// errSoftDeleted reports an operation that a soft-deleted key does not
// allow, with the mapping of errWrongState. Revoke, Destroy and ReKey
// retention soft-delete a key. Get and the cryptographic operations do not
// read the record that tells which, so the message names no State.
func errSoftDeleted(uid string) error {
	return operationErrorf(
		kmiplib.ResultReasonPermissionDenied,
		"wrong key lifecycle state: the key of object %q is soft-deleted in transit", uid,
	)
}
