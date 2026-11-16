// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/v2/internal/helper/testhelpers/certhelpers"
)

// testPKI is a CA with a server certificate for 127.0.0.1 and a client
// certificate.
type testPKI struct {
	ca     certhelpers.Certificate
	server certhelpers.Certificate
	client certhelpers.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()

	ca := certhelpers.NewCert(
		t,
		certhelpers.CommonName("kmip-test-ca"),
		certhelpers.IsCA(true),
		certhelpers.SelfSign(),
	)
	return testPKI{
		ca: ca,
		server: certhelpers.NewCert(
			t,
			certhelpers.CommonName("localhost"),
			certhelpers.Parent(ca),
			certhelpers.IP("127.0.0.1"),
			certhelpers.DNS("localhost"),
		),
		client: certhelpers.NewCert(
			t,
			certhelpers.CommonName("kmip-client"),
			certhelpers.Parent(ca),
		),
	}
}

// listen opens a TLS listener that requires a client certificate from the
// CA, as a kmip listener does.
func (p testPKI) listen(t *testing.T) net.Listener {
	t.Helper()

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(p.ca.Pem))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{p.server.TLSCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	return ln
}

func (p testPKI) dial(t *testing.T, addr string) *kmipclient.Client {
	t.Helper()

	c, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(p.ca.Pem),
		kmipclient.WithServerName("localhost"),
		kmipclient.WithClientCertPEM(p.client.Pem, p.client.PrivKey.Pem),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// startServer serves KMIP on ln until the test ends.
func startServer(t *testing.T, ln net.Listener, handler http.Handler) *Server {
	t.Helper()

	return startConfiguredServer(t, ln, handler, Config{AuthMount: "auth/cert"})
}

func startConfiguredServer(t *testing.T, ln net.Listener, handler http.Handler, cfg Config) *Server {
	t.Helper()
	srv, err := NewServer(ln, handler, cfg)
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		require.NoError(t, <-served)
	})
	return srv
}

// A client that connects and never sends a TLS handshake must not hold up
// Shutdown, which kmip-go would otherwise wait on forever.
func TestServer_ShutdownWithStalledHandshake(t *testing.T) {
	pki := newTestPKI(t)
	srv := startServer(t, pki.listen(t), newFakeBao(t))

	conn, err := net.Dial("tcp", srv.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Give the server time to accept the connection and start waiting on it.
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	require.NoError(t, srv.Shutdown(ctx))
	require.Less(t, time.Since(start), handshakeTimeout)

	// The server closed the stalled connection rather than leaving it open.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	var netErr net.Error
	require.False(t, errors.As(err, &netErr) && netErr.Timeout(), "connection still open: %v", err)
}

func TestServer_ConnectionsRevokeTheirTokens(t *testing.T) {
	pki := newTestPKI(t)
	bao := newFakeBao(t)
	bao.fallback = func(r fakeRequest) (int, any) {
		switch {
		case r.method == http.MethodGet && strings.HasSuffix(r.path, "/metadata"):
			// Create stores the template's Cryptographic Usage Mask.
			return http.StatusOK, withData(map[string]any{"custom_metadata": map[string]string{}, "version": 0})
		case r.method == http.MethodPost && strings.HasPrefix(r.path, "transit/keys/"):
			return http.StatusOK, withData(keyData("aes256-gcm96", nil))
		}
		return http.StatusNotFound, withErrors()
	}
	srv := startServer(t, pki.listen(t), bao)

	first := pki.dial(t, srv.Addr().String())
	_, err := first.Create().AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).WithName("app-a").Exec()
	require.NoError(t, err)

	second := pki.dial(t, srv.Addr().String())
	_, err = second.Create().AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).WithName("app-b").Exec()
	require.NoError(t, err)

	// Each connection logged in once, as the client's certificate and address.
	logins := bao.sent(http.MethodPost, testLoginPath)
	require.Len(t, logins, 2)
	for _, login := range logins {
		require.Len(t, login.peerCerts, 1)
		require.Equal(t, pki.client.RawCert, login.peerCerts[0].Raw)
		host, _, err := net.SplitHostPort(login.remoteAddr)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", host)
	}

	// Closing a connection revokes its token.
	require.NoError(t, first.Close())
	require.Eventually(t, func() bool {
		return len(bao.sent(http.MethodPost, testRevokePath)) == 1
	}, 5*time.Second, 10*time.Millisecond)

	// Shutdown ends the open connection, which revokes its token as well.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require.NoError(t, srv.Shutdown(ctx))

	revokes := bao.sent(http.MethodPost, testRevokePath)
	require.Len(t, revokes, 2)
	require.ElementsMatch(t, []string{"token-1", "token-2"}, []string{revokes[0].token, revokes[1].token})
}

// flakyListener fails its first Accept, then hands out one conn, then
// blocks until closed.
type flakyListener struct {
	net.Listener
	conns  chan net.Conn
	closed chan struct{}
	calls  int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.calls++
	if f.calls == 1 {
		return nil, errors.New("accept: too many open files")
	}
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

func (f *flakyListener) Close() error {
	close(f.closed)
	return nil
}

func TestHandshakeListener_SurvivesAcceptError(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	fl := &flakyListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	fl.conns <- server

	l := newHandshakeListener(fl, time.Second)
	conn, err := l.Accept()
	require.NoError(t, err)
	require.Same(t, server, conn)

	require.NoError(t, l.Close())
	_, err = l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestServerLimitsAndReload(t *testing.T) {
	pki := newTestPKI(t)
	bao := newFakeBao(t)
	auditor := new(recordingAuditor)
	cfg := Config{AuthMount: "auth/cert", MaxConnections: 1, Auditor: auditor}
	ln := newMemoryListener(t, pki)
	srv := startConfiguredServer(t, ln, bao, cfg)
	first := ln.client(t, pki)
	_, err := first.Query().Exec()
	require.NoError(t, err)
	require.Equal(t, int64(1), srv.ln.active.Load())
	second, err := ln.dial(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = second.Close() }()
	require.NoError(t, second.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = second.Read(make([]byte, 1))
	require.Error(t, err)
	cfg.MaxConnections = 2
	cfg.MaxMessageSize = 512
	cfg.IdleTimeout = time.Minute
	require.NoError(t, srv.Reload(cfg))
	next := ln.client(t, pki)
	_, err = next.Query().Exec()
	require.NoError(t, err)
	require.Equal(t, int64(2), srv.ln.active.Load())
	require.NoError(t, first.Close())
	require.NoError(t, next.Close())
	require.Eventually(t, func() bool { return srv.ln.active.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	cfg.MaxConnections = -1
	require.Error(t, srv.Reload(cfg))
	require.Equal(t, int64(2), srv.ln.maxConnections.Load())
}

func TestServerWireRefusals(t *testing.T) {
	pki := newTestPKI(t)
	for _, name := range []string{"empty batch", "oversize", "malformed", "header", "bad payload", "nested length"} {
		t.Run(name, func(t *testing.T) {
			auditor := new(recordingAuditor)
			bao := newFakeBao(t)
			ln := newMemoryListener(t, pki)
			startConfiguredServer(t, ln, bao, Config{AuthMount: "auth/cert", Auditor: auditor, MaxMessageSize: 1024})
			conn := ln.rawDial(t, pki)
			req := &kmiplib.RequestMessage{Header: kmiplib.RequestHeader{ProtocolVersion: kmiplib.V1_4}}
			frame := ttlv.MarshalTTLV(req)
			switch name {
			case "oversize":
				frame = []byte{0x42, 0, 0x78, 1, 0, 0, 8, 0}
			case "malformed":
				frame = []byte{0x42, 0, 0x78, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}
			case "bad payload":
				// A Unique Identifier sent as an Integer: kmip-go drops the
				// item, but the audit record keeps its operation.
				req.BatchItem = []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationGet, RequestPayload: &payloads.GetRequestPayload{UniqueIdentifier: "app-key"}}}
				frame = ttlv.MarshalTTLV(req)
				at := bytes.Index(frame, []byte{0x42, 0x00, 0x94, byte(ttlv.TypeTextString)})
				require.Positive(t, at)
				frame[at+3] = byte(ttlv.TypeInteger)
			case "nested length":
				// A child longer than its parent makes kmip-go's decoder panic.
				frame = []byte{0x42, 0, 0x78, 1, 0, 0, 0, 8, 0x42, 0, 0x77, 1, 0, 0, 1, 0}
			case "header":
				req.Header.BatchCount = 2
				req.BatchItem = []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationQuery, RequestPayload: &payloads.QueryRequestPayload{}}}
				frame = ttlv.MarshalTTLV(req)
			}
			_, err := conn.Write(frame)
			require.NoError(t, err)
			var response kmiplib.ResponseMessage
			stream := ttlv.NewStream(conn, 1024)
			err = stream.Recv(&response)
			require.NoError(t, err)
			auditor.mu.Lock()
			defer auditor.mu.Unlock()
			require.Len(t, auditor.requests, 1)
			require.Len(t, auditor.responses, 1)
			in := auditor.requests[0]
			clientCert, err := x509.ParseCertificate(pki.client.RawCert)
			require.NoError(t, err)
			require.Equal(t, clientCert.SerialNumber, in.Request.Connection.ConnState.PeerCertificates[0].SerialNumber)
			require.Equal(t, clientCert.SerialNumber, in.Request.Connection.ConnState.VerifiedChains[0][0].SerialNumber)
			require.Equal(t, clientCert.Subject.String(), in.Request.Data["client_certificate_subject"])
			if name == "bad payload" {
				require.Equal(t, "Get", in.Request.Data["kmip_operation"])
				require.Equal(t, kmiplib.ResultReasonInvalidMessage, response.BatchItem[0].ResultReason)
			}
			require.Empty(t, bao.all())
		})
	}
}

// Two connections with one address must each keep their own session. The
// first one accepted completes its handshake last.
func TestServerConnectionsShareAddress(t *testing.T) {
	pki := newTestPKI(t)
	ln := newMemoryListener(t, pki)
	ln.sameAddr = true
	startConfiguredServer(t, ln, newFakeBao(t), Config{AuthMount: "auth/cert"})

	first, err := ln.dial(t.Context(), "")
	require.NoError(t, err)
	second := ln.client(t, pki)
	_, err = second.Query().Exec()
	require.NoError(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pki.ca.Pem))
	tlsFirst := tls.Client(first, &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{pki.client.TLSCert}, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = tlsFirst.Close() })
	require.NoError(t, tlsFirst.HandshakeContext(t.Context()))
	c, err := kmipclient.Dial("memory", kmipclient.WithDialerUnsafe(func(context.Context, string) (net.Conn, error) { return tlsFirst, nil }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.Query().Exec()
	require.NoError(t, err)
	_, err = second.Query().Exec()
	require.NoError(t, err)
}

func TestServerIdlePartialFrameRevokesToken(t *testing.T) {
	pki := newTestPKI(t)
	bao := newFakeBao(t)
	bao.fallback = func(r fakeRequest) (int, any) { return http.StatusOK, withData(keyData("aes256-gcm96", nil)) }
	ln := newMemoryListener(t, pki)
	srv := startConfiguredServer(t, ln, bao, Config{AuthMount: "auth/cert", IdleTimeout: 300 * time.Millisecond})
	conn := ln.rawDial(t, pki)
	req := &kmiplib.RequestMessage{Header: kmiplib.RequestHeader{ProtocolVersion: kmiplib.V1_4, BatchCount: 1}, BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationCreate, RequestPayload: &payloads.CreateRequestPayload{ObjectType: kmiplib.ObjectTypeSymmetricKey, TemplateAttribute: kmiplib.TemplateAttribute{Attribute: []kmiplib.Attribute{{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: kmiplib.CryptographicAlgorithmAES}, {AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(256)}}}}}}}
	_, err := conn.Write(ttlv.MarshalTTLV(req))
	require.NoError(t, err)
	var resp kmiplib.ResponseMessage
	stream := ttlv.NewStream(conn, 1<<20)
	require.NoError(t, stream.Recv(&resp))
	require.Equal(t, kmiplib.ResultStatusSuccess, resp.BatchItem[0].ResultStatus)
	_, err = conn.Write(ttlv.MarshalTTLV(req)[:8])
	require.NoError(t, err)
	for range 3 {
		time.Sleep(70 * time.Millisecond)
		_, err = conn.Write([]byte{0x42})
		require.NoError(t, err)
	}
	go func() { _, _ = io.Copy(io.Discard, conn) }()
	require.Eventually(t, func() bool { return len(bao.sent(http.MethodPost, testRevokePath)) == 1 }, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return srv.ln.active.Load() == 0 }, time.Second, 10*time.Millisecond)
}

func TestServerHandshakeFailureReleasesSlot(t *testing.T) {
	pki := newTestPKI(t)
	ln := newMemoryListener(t, pki)
	srv := startConfiguredServer(t, ln, newFakeBao(t), Config{AuthMount: "auth/cert", MaxConnections: 1})
	conn, err := ln.dial(t.Context(), "")
	require.NoError(t, err)
	_, err = conn.Write([]byte("not TLS"))
	require.NoError(t, err)
	_ = conn.Close()
	require.Eventually(t, func() bool { return srv.ln.active.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
	_, err = ln.client(t, pki).Query().Exec()
	require.NoError(t, err)
}

// memoryListener exercises the real TLS, framing and server hooks without a
// listening socket. Each connection has a distinct address, as with TCP.
type memoryListener struct {
	conns    chan net.Conn
	done     chan struct{}
	once     sync.Once
	sequence atomic.Int32
	cfg      *tls.Config
	// sameAddr gives every connection the same address, as two TCP
	// connections from one source to two local addresses can have.
	sameAddr bool
}

type memoryPeer struct {
	net.Conn
	remote net.Addr
}

func (c *memoryPeer) RemoteAddr() net.Addr { return c.remote }
func (l *memoryListener) Addr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5696} }
func (l *memoryListener) Close() error     { l.once.Do(func() { close(l.done) }); return nil }
func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func newMemoryListener(t *testing.T, p testPKI) *memoryListener {
	t.Helper()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(p.ca.Pem))
	l := &memoryListener{conns: make(chan net.Conn), done: make(chan struct{}), cfg: &tls.Config{Certificates: []tls.Certificate{p.server.TLSCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func (l *memoryListener) dial(ctx context.Context, _ string) (net.Conn, error) {
	server, client := net.Pipe()
	port := int(l.sequence.Add(1)) + 10000
	if l.sameAddr {
		port = 10000
	}
	server = &memoryPeer{Conn: server, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}}
	select {
	case l.conns <- tls.Server(server, l.cfg):
		return client, nil
	case <-ctx.Done():
		_ = server.Close()
		_ = client.Close()
		return nil, ctx.Err()
	}
}

func (l *memoryListener) client(t *testing.T, p testPKI) *kmipclient.Client {
	t.Helper()
	c, err := kmipclient.Dial("memory", kmipclient.WithDialerUnsafe(func(context.Context, string) (net.Conn, error) { return l.rawDial(t, p), nil }), kmipclient.WithRootCAPem(p.ca.Pem), kmipclient.WithServerName("localhost"), kmipclient.WithClientCertPEM(p.client.Pem, p.client.PrivKey.Pem))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (l *memoryListener) rawDial(t *testing.T, p testPKI) *tls.Conn {
	t.Helper()
	conn, err := l.dial(t.Context(), "")
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(p.ca.Pem))
	c := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{p.client.TLSCert}, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, c.HandshakeContext(t.Context()))
	return c
}
