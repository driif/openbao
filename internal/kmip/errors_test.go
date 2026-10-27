// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"errors"
	"fmt"
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/stretchr/testify/require"
)

// mapError must keep the reason of a classified error, wrapped or not.
// kmipserver.Errorf returns a value, not a pointer.
func TestMapError_KeepsReason(t *testing.T) {
	cases := []struct {
		err    error
		reason kmiplib.ResultReason
	}{
		{errNotFound("k"), kmiplib.ResultReasonItemNotFound},
		{fmt.Errorf("locate: %w", errNotFound("k")), kmiplib.ResultReasonItemNotFound},
		{kmipserver.ErrPermissionDenied, kmiplib.ResultReasonPermissionDenied},
		{errors.New("boom"), kmiplib.ResultReasonGeneralFailure},
	}
	for _, tc := range cases {
		got, ok := errors.AsType[kmipserver.Error](mapError(tc.err))
		require.True(t, ok)
		require.Equal(t, tc.reason, got.Reason, tc.err.Error())
	}
}
