// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

//go:build kmipdump

package kmip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// dumpEnv names the directory a kmipdump build writes TTLV messages to.
const dumpEnv = "BAO_KMIP_TTLV_DUMP"

// dumpMiddleware writes every request message and its response, TTLV
// encoded, to NNN.req.ttlv and NNN.resp.ttlv in the directory named by
// BAO_KMIP_TTLV_DUMP, numbered across all connections of the listener. The
// files hold key material in the clear. Only a build with the kmipdump tag
// has it, and only when the variable is set.
func dumpMiddleware(logger hclog.Logger) kmipserver.Middleware {
	dir := os.Getenv(dumpEnv)
	if dir == "" {
		return nil
	}
	logger.Warn("dumping KMIP messages, key material included", "dir", dir)

	var n atomic.Int64
	return func(next kmipserver.Next, ctx context.Context, msg *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		resp, err := next(ctx, msg)

		i := n.Add(1)
		write := func(kind string, data any) {
			name := filepath.Join(dir, fmt.Sprintf("%03d.%s.ttlv", i, kind))
			if err := os.WriteFile(name, ttlv.MarshalTTLV(data), 0o600); err != nil {
				logger.Warn("failed to dump KMIP message", "file", name, "error", err)
			}
		}
		write("req", msg)
		if resp != nil {
			write("resp", resp)
		}
		return resp, err
	}
}
