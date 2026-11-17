// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

//go:build !kmipdump

package kmip

import (
	"github.com/hashicorp/go-hclog"
	"github.com/ovh/kmip-go/kmipserver"
)

// dumpMiddleware is nil outside a kmipdump build: no message is written.
func dumpMiddleware(hclog.Logger) kmipserver.Middleware {
	return nil
}
