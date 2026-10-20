// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"errors"
	"net/http"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// mapError returns err as a KMIP error. Errors the translator has already
// classified pass through; anything else is a General Failure.
func mapError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := errors.AsType[kmipserver.Error](err); ok {
		return err
	}

	return kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "%s", err.Error())
}

// failure turns an unsuccessful reply into a KMIP error. A 403 names the
// path and the capability the call needed, since that is what an operator
// has to grant.
func (r *reply) failure() error {
	switch r.status {
	case http.StatusForbidden:
		return kmipserver.Errorf(
			kmiplib.ResultReasonPermissionDenied,
			"permission denied: %s %s requires the %q capability", r.method, r.path, r.capability,
		)
	case http.StatusNotFound:
		return kmipserver.Errorf(kmiplib.ResultReasonItemNotFound, "%s not found", r.path)
	case http.StatusBadRequest:
		return kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "%s %s: %s", r.method, r.path, r.message())
	default:
		return kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "%s %s: status %d: %s", r.method, r.path, r.status, r.message())
	}
}

func errNotFound(uid string) error {
	return kmipserver.Errorf(kmiplib.ResultReasonItemNotFound, "object %q not found", uid)
}

// errSoftDeleted reports an operation that a soft-deleted (Deactivated) key
// does not allow. KMIP 1.x, which kmip-go serves, has no Wrong Key Lifecycle
// State result reason (it arrived in KMIP 2.0), so this is Permission Denied
// with a message that names the state.
func errSoftDeleted(uid string) error {
	return kmipserver.Errorf(
		kmiplib.ResultReasonPermissionDenied,
		"wrong key lifecycle state: object %q is Deactivated (soft-deleted in transit)", uid,
	)
}
