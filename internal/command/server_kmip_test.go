// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/v2/internal/helper/listenerutil"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/certhelpers"
	"github.com/openbao/openbao/v2/internal/kmip"
)

// countingListener counts how often it is closed.
type countingListener struct {
	net.Listener
	closes atomic.Int32
}

func (l *countingListener) Close() error {
	l.closes.Add(1)
	return l.Listener.Close()
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return &countingListener{Listener: ln}
}

// Each listener is closed exactly once: by the HTTP or KMIP server that
// serves it, or by close when no server took it over.
func TestRunningServers_CloseClosesEachListenerOnce(t *testing.T) {
	httpLn, kmipLn, unservedLn := newCountingListener(t), newCountingListener(t), newCountingListener(t)

	httpSrv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	httpServed := make(chan error, 1)
	go func() { httpServed <- httpSrv.Serve(httpLn) }()

	kmipSrv, err := kmip.NewServer(kmipLn, http.NotFoundHandler(), kmip.Config{AuthMount: "auth/cert"})
	require.NoError(t, err)
	kmipServed := make(chan error, 1)
	go func() { kmipServed <- kmipSrv.Serve() }()

	r := &runningServers{
		http:     []*http.Server{httpSrv},
		kmip:     []*kmip.Server{kmipSrv},
		unserved: []listenerutil.Listener{{Listener: unservedLn}},
	}
	require.NoError(t, r.close())

	require.ErrorIs(t, <-httpServed, http.ErrServerClosed)
	require.NoError(t, <-kmipServed)
	for name, ln := range map[string]*countingListener{"http": httpLn, "kmip": kmipLn, "unserved": unservedLn} {
		require.Equal(t, int32(1), ln.closes.Load(), name)
	}
}

func TestServer_RecoveryModeSkipsKMIPListeners(t *testing.T) {
	ui, cmd := testServerCommand(t)

	// The certificate files do not exist, so only a skipped listener lets
	// the server start.
	config := testBaseHCL(t, "") + `
listener "kmip" {
  address            = "127.0.0.1:0"
  tls_cert_file      = "/nonexistent/kmip.pem"
  tls_key_file       = "/nonexistent/kmip.key"
  tls_client_ca_file = "/nonexistent/ca.pem"
  auth_mount         = "auth/cert"
}
` + inmemHCL
	configFile := filepath.Join(t.TempDir(), "recovery.hcl")
	require.NoError(t, os.WriteFile(configFile, []byte(config), 0o600))

	code := cmd.Run([]string{"-test-verify-only", "-recovery", "-config", configFile})
	output := ui.ErrorWriter.String() + ui.OutputWriter.String()
	require.Equal(t, 0, code, output)
	require.Contains(t, output, `Not starting the kmip listener on "127.0.0.1:0"`)
}

// SIGHUP reloads the certificate of every kmip listener, not just one.
func TestServer_ReloadKMIPListeners(t *testing.T) {
	td := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(td, "kmip.pem"), filepath.Join(td, "kmip.key"), filepath.Join(td, "ca.pem")

	ca := certhelpers.NewCert(
		t,
		certhelpers.CommonName("kmip-reload-ca"),
		certhelpers.IsCA(true),
		certhelpers.SelfSign(),
	)
	client := certhelpers.NewCert(t, certhelpers.CommonName("kmip-client"), certhelpers.Parent(ca))
	require.NoError(t, os.WriteFile(caFile, ca.Pem, 0o600))

	writeServerCert := func(cn string) {
		cert := certhelpers.NewCert(
			t,
			certhelpers.CommonName(cn),
			certhelpers.Parent(ca),
			certhelpers.IP("127.0.0.1"),
		)
		require.NoError(t, os.WriteFile(certFile, cert.Pem, 0o600))
		require.NoError(t, os.WriteFile(keyFile, cert.PrivKey.Pem, 0o600))
	}
	writeServerCert("foo.example.com")

	kmipAddrs := []string{freeAddr(t), freeAddr(t)}
	var config strings.Builder
	fmt.Fprintf(&config, `
backend "inmem" {}
listener "tcp" {
  address     = %q
  tls_disable = true
}
`, freeAddr(t))
	for _, addr := range kmipAddrs {
		fmt.Fprintf(&config, `
listener "kmip" {
  address            = %q
  tls_cert_file      = %q
  tls_key_file       = %q
  tls_client_ca_file = %q
  auth_mount         = "auth/cert"
}
`, addr, certFile, keyFile, caFile)
	}
	configFile := filepath.Join(td, "kmip.hcl")
	require.NoError(t, os.WriteFile(configFile, []byte(config.String()), 0o600))

	ui, cmd := testServerCommand(t)
	exited := make(chan int, 1)
	go func() { exited <- cmd.Run([]string{"-config", configFile}) }()

	select {
	case <-cmd.startedCh:
	case code := <-exited:
		t.Fatalf("server exited with %d: %s", code, ui.ErrorWriter.String()+ui.OutputWriter.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the server to start")
	}

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.Pem))
	servedName := func(addr string) string {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{client.TLSCert},
			MinVersion:   tls.VersionTLS12,
		})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	for _, addr := range kmipAddrs {
		require.Equal(t, "foo.example.com", servedName(addr), addr)
	}

	writeServerCert("bar.example.com")
	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the reload")
	}
	for _, addr := range kmipAddrs {
		require.Equal(t, "bar.example.com", servedName(addr), addr)
	}

	cmd.ShutdownCh <- struct{}{}
	select {
	case code := <-exited:
		require.Equal(t, 0, code, ui.ErrorWriter.String()+ui.OutputWriter.String())
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for the server to stop")
	}
}

// freeAddr returns a local address with a port nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}
