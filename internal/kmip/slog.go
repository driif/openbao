// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"log/slog"

	"github.com/hashicorp/go-hclog"
)

// SlogHandler returns a slog handler that writes to logger, at ceiling at
// most. kmip-go logs through slog and has no option to set a logger: a
// server keeps the slog default that is current when it is made.
func SlogHandler(logger hclog.Logger, ceiling hclog.Level) slog.Handler {
	return slogHandler{logger: logger, ceiling: ceiling}
}

type slogHandler struct {
	logger  hclog.Logger
	ceiling hclog.Level
}

func (h slogHandler) level(l slog.Level) hclog.Level {
	level := hclog.Error
	switch {
	case l < slog.LevelInfo:
		level = hclog.Debug
	case l < slog.LevelWarn:
		level = hclog.Info
	case l < slog.LevelError:
		level = hclog.Warn
	}
	return min(level, h.ceiling)
}

func (h slogHandler) Enabled(_ context.Context, l slog.Level) bool {
	return h.logger.GetLevel() <= h.level(l)
}

func (h slogHandler) Handle(_ context.Context, r slog.Record) error {
	args := make([]any, 0, 2*r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		args = append(args, a.Key, a.Value.Any())
		return true
	})
	h.logger.Log(h.level(r.Level), r.Message, args...)
	return nil
}

func (h slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	args := make([]any, 0, 2*len(attrs))
	for _, a := range attrs {
		args = append(args, a.Key, a.Value.Any())
	}
	return slogHandler{logger: h.logger.With(args...), ceiling: h.ceiling}
}

func (h slogHandler) WithGroup(name string) slog.Handler {
	return slogHandler{logger: h.logger.Named(name), ceiling: h.ceiling}
}
