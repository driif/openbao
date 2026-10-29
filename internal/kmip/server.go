// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/ovh/kmip-go/kmipserver"
)

// handshakeTimeout bounds a client's TLS handshake.
const handshakeTimeout = 10 * time.Second

// Config is the KMIP side of a kmip listener's configuration.
type Config struct {
	// AuthMount is the namespace-qualified cert auth mount clients log in
	// through, such as auth/cert or tenant-a/auth/cert.
	AuthMount string

	// DefaultTransitMount is the transit mount, in the auth mount's
	// namespace, for clients whose cert role sets no kmip_transit_mount.
	DefaultTransitMount string

	Logger hclog.Logger
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

	exec := kmipserver.NewBatchExecutor()
	if dump := dumpMiddleware(t.logger); dump != nil {
		exec.Use(dump)
	}
	for op, h := range routes() {
		exec.Route(op, h)
	}

	hl := newHandshakeListener(ln, handshakeTimeout)
	srv := kmipserver.NewServer(hl, exec).
		WithConnectHook(t.connect).
		WithTerminateHook(terminate)

	return &Server{kmip: srv, ln: hl}, nil
}

// connect gives each connection its own session.
func (t *translator) connect(ctx context.Context) (context.Context, error) {
	certs := kmipserver.PeerCertificates(ctx)
	if len(certs) == 0 {
		return nil, errors.New("client certificate required")
	}
	return context.WithValue(ctx, sessionKey{}, t.newSession(certs, kmipserver.RemoteAddr(ctx))), nil
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
	closeOnce sync.Once
	closeErr  error
}

func newHandshakeListener(ln net.Listener, timeout time.Duration) *handshakeListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &handshakeListener{
		Listener: ln,
		timeout:  timeout,
		ready:    make(chan net.Conn),
		failed:   make(chan error, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	l.start.Do(func() {
		go l.acceptLoop()
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
		go l.handshake(conn)
	}
}

func (l *handshakeListener) handshake(conn net.Conn) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(l.ctx, l.timeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			_ = conn.Close()
			return
		}
	}

	select {
	case l.ready <- conn:
	case <-l.ctx.Done():
		_ = conn.Close()
	}
}
