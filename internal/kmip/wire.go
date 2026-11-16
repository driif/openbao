// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// wireConn validates a bounded complete frame before kmip-go sees any bytes.
// It also keeps the verified TLS state, since wrapping hides *tls.Conn.
// Only the read loop uses pending and the idle deadline. connected publishes
// the context from the connect hook before that loop may inspect a request.
type wireConn struct {
	net.Conn
	id        uint64
	listener  *handshakeListener
	state     *tls.ConnectionState
	connected chan struct{}
	done      chan struct{}
	ctx       context.Context
	delivered atomic.Bool
	closeOnce sync.Once
	closeErr  error
	writeMu   sync.Mutex
	idle      time.Duration
	maxSize   int64
	pending   []byte
	deadline  time.Time
}

func (c *wireConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.closeErr = c.Conn.Close()
		l := c.listener
		l.mu.Lock()
		delete(l.connections, c.id)
		l.mu.Unlock()
		l.metrics.mu.Lock()
		delete(l.metrics.clients, c)
		l.metrics.mu.Unlock()
		l.metrics.gauge("connections_open", float32(l.active.Add(-1)))
		l.metrics.refresh()
	})
	return c.closeErr
}

// RemoteAddr adds the connection's ID to the client's address, so the connect
// hook finds this connection even when another one has the same address.
func (c *wireConn) RemoteAddr() net.Addr {
	return connAddr{Addr: c.Conn.RemoteAddr(), id: c.id}
}

type connAddr struct {
	net.Addr
	id uint64
}

func (a connAddr) String() string { return a.Addr.String() + "#" + strconv.FormatUint(a.id, 10) }

func (c *wireConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}

func (c *wireConn) Read(p []byte) (int, error) {
	select {
	case <-c.connected:
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.listener.ctx.Done():
		return 0, net.ErrClosed
	}
	if len(c.pending) == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *wireConn) readFrame() error {
	if c.deadline.IsZero() {
		c.deadline = time.Now().Add(c.idle)
	}
	if err := c.SetReadDeadline(c.deadline); err != nil {
		return err
	}
	var header [8]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			c.refuse(nil, kmiplib.ResultReasonInvalidMessage)
		}
		return err
	}
	size := int64(binary.BigEndian.Uint32(header[4:]))
	total := 8 + ((size + 7) &^ 7)
	if total > c.maxSize {
		c.refuse(nil, kmiplib.ResultReasonInvalidMessage)
		return io.EOF
	}
	frame := make([]byte, int(total))
	copy(frame, header[:])
	if _, err := io.ReadFull(c.Conn, frame[8:]); err != nil {
		// An idle timeout must end the session immediately. Trying to write a
		// malformed-frame reply here can wait on an unresponsive peer and
		// delay the terminate hook and token revocation.
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			c.refuse(nil, kmiplib.ResultReasonInvalidMessage)
		}
		return err
	}
	req := new(kmiplib.RequestMessage)
	if err := decodeRequest(frame, req); err != nil {
		// kmip-go keeps a batch item only once its payload decodes, so take
		// the items from the frame itself.
		if items := outline(frame); len(items) >= len(req.BatchItem) {
			req.BatchItem = items
		}
		c.refuse(req, kmiplib.ResultReasonInvalidMessage)
		return io.EOF
	}
	c.deadline = time.Now().Add(c.idle)
	c.pending = frame
	return nil
}

// refuse never passes a decoder error or an untrusted payload to the audit
// formatter or the reply. Partially decoded messages retain operation IDs only.
func (c *wireConn) refuse(req *kmiplib.RequestMessage, reason kmiplib.ResultReason) {
	if req == nil {
		req = &kmiplib.RequestMessage{}
	}
	if req.Header.ProtocolVersion == (kmiplib.ProtocolVersion{}) {
		req.Header.ProtocolVersion = kmiplib.V1_4
	}
	if len(req.BatchItem) == 0 {
		req.BatchItem = []kmiplib.RequestBatchItem{{}}
	}
	for i := range req.BatchItem {
		req.BatchItem[i].RequestPayload = nil
	}
	resp, _ := c.listener.audit.message(func(context.Context, *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		return nil, kmipserver.Errorf(reason, "%s", safeResultMessage(reason))
	}, c.ctx, req)
	_ = c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	_, _ = c.Write(ttlv.MarshalTTLV(resp))
}

// decodeRequest decodes frame into req. kmip-go's decoder panics on some
// nested lengths that do not fit their parent, and nothing above this read
// recovers, so a panic here would stop the process. It becomes a decode
// error instead.
func decodeRequest(frame []byte, req *kmiplib.RequestMessage) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("malformed TTLV frame")
		}
	}()
	return ttlv.UnmarshalTTLV(frame, req)
}

// outline reads the Operation and the Unique Batch Item ID of each batch item
// in frame, and skips the payloads. A frame that kmip-go cannot decode still
// gets one audit pair per batch item under its operation name. It stops at
// the first item it cannot read, and keeps that item with what it read.
func outline(frame []byte) (items []kmiplib.RequestBatchItem) {
	defer func() { _ = recover() }()
	dec, err := ttlv.NewTTLVDecoder(frame)
	if err != nil {
		return nil
	}
	_ = dec.Struct(kmiplib.TagRequestMessage, func(d *ttlv.Decoder) error {
		for d.Tag() != 0 {
			if d.Tag() != kmiplib.TagBatchItem {
				if err := d.Next(); err != nil {
					return err
				}
				continue
			}
			var item kmiplib.RequestBatchItem
			err := d.Struct(kmiplib.TagBatchItem, func(d *ttlv.Decoder) error {
				if err := d.Any(&item.Operation); err != nil {
					return err
				}
				return d.Opt(kmiplib.TagUniqueBatchItemID, &item.UniqueBatchItemID)
			})
			items = append(items, item)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return items
}
