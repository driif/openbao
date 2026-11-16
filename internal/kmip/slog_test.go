// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestSlogHandler(t *testing.T) {
	newLogger := func(level, ceiling hclog.Level) (*slog.Logger, *bytes.Buffer) {
		var out bytes.Buffer
		logger := hclog.New(&hclog.LoggerOptions{Name: "kmip", Level: level, Output: &out, DisableTime: true})
		return slog.New(SlogHandler(logger, ceiling)), &out
	}

	t.Run("levels and attributes", func(t *testing.T) {
		log, out := newLogger(hclog.Debug, hclog.Error)
		log.With("addr", "10.0.0.1:5696").Info("New connection", "id", 7)
		log.Debug("read fail")
		log.Warn("Shutting down")
		log.Error("Failed to read data from client")
		require.Equal(t, ""+
			"[INFO]  kmip: New connection: addr=10.0.0.1:5696 id=7\n"+
			"[DEBUG] kmip: read fail\n"+
			"[WARN]  kmip: Shutting down\n"+
			"[ERROR] kmip: Failed to read data from client\n", out.String())
	})

	// kmip-go reports each connection at Info and each client reset at
	// Error. With a Debug ceiling they do not reach a log at the Info level.
	t.Run("ceiling", func(t *testing.T) {
		log, out := newLogger(hclog.Info, hclog.Debug)
		log.Info("New connection")
		log.Error("Failed to read data from client")
		require.Empty(t, out.String())

		log, out = newLogger(hclog.Debug, hclog.Debug)
		log.Error("Failed to read data from client")
		require.Equal(t, "[DEBUG] kmip: Failed to read data from client\n", out.String())
	})
}
