// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
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

	srv, err := NewServer(ln, handler, Config{AuthMount: "auth/cert"})
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
		if r.method == http.MethodPost && strings.HasPrefix(r.path, "transit/keys/") {
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
