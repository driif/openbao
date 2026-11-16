// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	"github.com/ovh/kmip-go/kmipserver"
)

// handshakeTimeout bounds a client's TLS handshake.
const handshakeTimeout = 10 * time.Second

// Auditor sends operation records to the core without coupling KMIP to vault.
type Auditor interface {
	AuditRequest(context.Context, string, *logical.LogInput) error
	AuditResponse(context.Context, string, *logical.LogInput) error
}

const (
	defaultMaxConnections = 1024
	defaultIdleTimeout    = 10 * time.Minute
)

// DefaultMaxMessageSize is the frame limit of a kmip listener without
// max_request_size.
const DefaultMaxMessageSize = 1 << 20

// Config is the KMIP side of a kmip listener's configuration.
type Config struct {
	// AuthMount is the namespace-qualified cert auth mount clients log in
	// through, such as auth/cert or tenant-a/auth/cert.
	AuthMount string

	// DefaultTransitMount is the transit mount, in the auth mount's
	// namespace, for clients whose cert role sets no kmip_transit_mount.
	DefaultTransitMount string

	Logger            hclog.Logger
	Auditor           Auditor
	Metrics           *metricsutil.ClusterMetricSink
	MaxConnections    int
	IdleTimeout       time.Duration
	MaxMessageSize    int64
	ServerCertificate func() *x509.Certificate
}

// Server serves KMIP on one listener.
type Server struct {
	kmip *kmipserver.Server
	ln   *handshakeListener
}

// NewServer returns a KMIP server for ln, which must hand out TLS
// connections with verified client certificates. Each KMIP operation becomes
// requests to handler, normally the OpenBao HTTP handler for the listener.
func NewServer(ln net.Listener, handler http.Handler, cfg Config) (*Server, error) {
	t, err := newTranslator(handler, cfg)
	if err != nil {
		return nil, err
	}

	sink := cfg.Metrics
	if sink == nil {
		sink = metricsutil.BlackholeSink()
	}
	m := &listenerMetrics{sink: sink, address: ln.Addr().String(), clients: make(map[*wireConn]*x509.Certificate), certificate: cfg.ServerCertificate}
	a := &operationAuditor{auditor: cfg.Auditor, namespace: t.namespace, metrics: m}
	exec := kmipserver.NewBatchExecutor()
	exec.Use(a.message)
	exec.BatchItemUse(a.item)
	if dump := dumpMiddleware(t.logger); dump != nil {
		exec.Use(dump)
	}
	for op, h := range routes() {
		exec.Route(op, h)
	}

	hl := newHandshakeListener(ln, handshakeTimeout)
	hl.t, hl.audit, hl.metrics = t, a, m
	if err := hl.reload(cfg); err != nil {
		return nil, err
	}
	srv := kmipserver.NewServer(hl, exec).
		WithMaxMessageSize(-1).
		WithConnectHook(hl.connect).
		WithTerminateHook(terminate)

	return &Server{kmip: srv, ln: hl}, nil
}

// connect receives the verified state explicitly: wireConn hides *tls.Conn
// from kmip-go, so PeerCertificates on its context is empty.
func (l *handshakeListener) connect(ctx context.Context) (context.Context, error) {
	// kmip-go passes only the address string; wireConn.RemoteAddr puts the
	// connection's ID in it, since two connections can share an address.
	// IDs start at 1, so an address without one finds no connection.
	addr := kmipserver.RemoteAddr(ctx)
	id, _ := strconv.ParseUint(addr[strings.LastIndexByte(addr, '#')+1:], 10, 64)
	l.mu.Lock()
	conn := l.connections[id]
	l.mu.Unlock()
	if conn == nil || conn.state == nil || len(conn.state.PeerCertificates) == 0 {
		return nil, errors.New("client certificate required")
	}
	s := l.t.newSession(conn.state.PeerCertificates, conn.Conn.RemoteAddr().String())
	s.connectionState = conn.state
	ctx = context.WithValue(ctx, sessionKey{}, s)
	conn.ctx = ctx
	close(conn.connected)
	return ctx, nil
}

// Reload applies connection limits to new connections and refreshes the
// certificate gauge. Existing connections keep their accepted limits.
func (s *Server) Reload(cfg Config) error { return s.ln.reload(cfg) }

func (l *handshakeListener) reload(cfg Config) error {
	if cfg.MaxConnections < 0 || cfg.IdleTimeout < 0 || cfg.MaxMessageSize < 0 {
		return errors.New("KMIP limits cannot be negative")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}
	l.maxConnections.Store(int64(cfg.MaxConnections))
	l.idleTimeout.Store(int64(cfg.IdleTimeout))
	l.maxMessageSize.Store(cfg.MaxMessageSize)
	if l.metrics != nil {
		l.metrics.mu.Lock()
		if cfg.ServerCertificate != nil {
			l.metrics.certificate = cfg.ServerCertificate
		}
		l.metrics.mu.Unlock()
		l.metrics.refresh()
	}
	return nil
}

func terminate(ctx context.Context) {
	if s, ok := ctx.Value(sessionKey{}).(*session); ok {
		s.close(ctx)
	}
}

// Serve accepts connections until Shutdown.
func (s *Server) Serve() error {
	err := s.kmip.Serve()
	if errors.Is(err, kmipserver.ErrShutdown) {
		return nil
	}
	return err
}

// Shutdown closes the listener and waits for open connections to end, which
// revokes their tokens. kmip-go cancels requests still running after three
// seconds; ctx bounds the rest.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- s.kmip.Shutdown()
	}()

	select {
	case err := <-done:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return fmt.Errorf("KMIP server on %s did not stop: %w", s.ln.Addr(), ctx.Err())
	}
}

// Addr is the listener's address.
func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

// handshakeListener completes each TLS handshake, under a deadline, before
// kmip-go sees the connection. kmip-go handshakes without a deadline and
// outside anything Shutdown can cancel, so one stalled client would
// otherwise hold Shutdown forever.
type handshakeListener struct {
	net.Listener
	timeout time.Duration

	start  sync.Once
	ready  chan net.Conn
	failed chan error
	ctx    context.Context
	cancel context.CancelFunc

	// The listener may be a tls_auto_reload listener, which panics when
	// closed twice.
	closeOnce      sync.Once
	closeErr       error
	t              *translator
	audit          *operationAuditor
	metrics        *listenerMetrics
	maxConnections atomic.Int64
	idleTimeout    atomic.Int64
	maxMessageSize atomic.Int64
	active         atomic.Int64
	nextID         atomic.Uint64
	mu             sync.Mutex
	connections    map[uint64]*wireConn
}

func newHandshakeListener(ln net.Listener, timeout time.Duration) *handshakeListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &handshakeListener{
		Listener:    ln,
		timeout:     timeout,
		ready:       make(chan net.Conn),
		failed:      make(chan error, 1),
		ctx:         ctx,
		cancel:      cancel,
		connections: make(map[uint64]*wireConn),
	}
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	l.start.Do(func() {
		go l.acceptLoop()
		if l.metrics != nil {
			go l.emitMetrics()
		}
	})

	select {
	case conn := <-l.ready:
		return conn, nil
	case err := <-l.failed:
		return nil, err
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *handshakeListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		l.closeErr = l.Listener.Close()
		l.mu.Lock()
		for _, conn := range l.connections {
			// kmip-go ends established connections through its terminate hook.
			// Cancel handshakes and connections not yet delivered to it here.
			if !conn.delivered.Load() {
				_ = conn.Conn.Close()
			}
		}
		l.mu.Unlock()
	})
	return l.closeErr
}

// acceptLoop stops only when the listener is closed. Any other Accept error
// (EMFILE, ECONNABORTED, a refused PROXY header) affects one connection, so
// it is retried with the same capped backoff net/http uses.
func (l *handshakeListener) acceptLoop() {
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || l.ctx.Err() != nil {
				l.failed <- err
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(delay):
				continue
			case <-l.ctx.Done():
				l.failed <- net.ErrClosed
				return
			}
		}
		delay = 0
		if l.t == nil {
			go l.handshake(conn)
			continue
		}
		if !l.acquire() {
			l.metrics.counter("connections_refused", metricsutil.Label{Name: "reason", Value: "limit"})
			_ = conn.Close()
			continue
		}
		// Do not read RemoteAddr here: with a PROXY listener it reads the
		// header from the client, and this loop must not wait on a client.
		c := &wireConn{Conn: conn, id: l.nextID.Add(1), listener: l, connected: make(chan struct{}), done: make(chan struct{}), idle: time.Duration(l.idleTimeout.Load()), maxSize: l.maxMessageSize.Load()}
		l.mu.Lock()
		l.connections[c.id] = c
		l.mu.Unlock()
		l.metrics.counter("connections_accepted")
		go l.handshake(c)
	}
}

func (l *handshakeListener) handshake(conn net.Conn) {
	raw := conn
	if c, ok := conn.(*wireConn); ok {
		raw = c.Conn
	}
	if tlsConn, ok := raw.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(l.ctx, l.timeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			if l.metrics != nil {
				l.metrics.counter("connections_refused", metricsutil.Label{Name: "reason", Value: "handshake"})
			}
			_ = conn.Close()
			return
		}
		if c, ok := conn.(*wireConn); ok {
			state := tlsConn.ConnectionState()
			c.state = &state
			if len(state.PeerCertificates) > 0 {
				l.metrics.mu.Lock()
				l.metrics.clients[c] = state.PeerCertificates[0]
				l.metrics.mu.Unlock()
				l.metrics.refresh()
			}
		}
	}
	if c, ok := conn.(*wireConn); ok {
		c.delivered.Store(true)
	}
	select {
	case l.ready <- conn:
	case <-l.ctx.Done():
		_ = conn.Close()
	}
}

// acquire is a counting semaphore whose capacity can change on reload.
func (l *handshakeListener) acquire() bool {
	for {
		n := l.active.Load()
		if n >= l.maxConnections.Load() {
			return false
		}
		if l.active.CompareAndSwap(n, n+1) {
			l.metrics.gauge("connections_open", float32(n+1))
			return true
		}
	}
}

func (l *handshakeListener) emitMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.metrics.refresh()
			l.metrics.gauge("connections_open", float32(l.active.Load()))
		case <-l.ctx.Done():
			return
		}
	}
}
