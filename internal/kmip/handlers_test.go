// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
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
