// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// generateTestCAWithKey returns a CA cert/key pair for deeper TLS testing.
func generateTestCAWithKey(t *testing.T) (certPEM, keyPEM string, privKey *ecdsa.PrivateKey, certDER []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-kmip-ca",
			Organization: []string{"TestCA"},
		},
		DNSNames:              []string{"test-kmip-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	var certBuf bytes.Buffer
	require.NoError(t, pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}))

	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	var keyBuf bytes.Buffer
	require.NoError(t, pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	return certBuf.String(), keyBuf.String(), priv, der
}

// freePort finds a free TCP port on loopback.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestKmipServer_StartStop(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	addr := freePort(t)

	cfg := &kmipConfig{
		Enabled:           true,
		ListenAddr:        addr,
		ServerCertPEM:     certPEM,
		ServerKeyPEM:      keyPEM,
		RequireClientCert: false,
	}

	b, _ := createBackendWithSysView(t)

	srv, err := newTransitKmipServer(cfg, b)
	require.NoError(t, err)
	require.NotNil(t, srv)

	srv.Start()

	// Verify listening address
	require.NotNil(t, srv.Addr())

	// Stop and verify no error
	err = srv.Stop()
	require.NoError(t, err)
}

func TestKmipServer_TLSConnection(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	addr := freePort(t)

	cfg := &kmipConfig{
		Enabled:           true,
		ListenAddr:        addr,
		ServerCertPEM:     certPEM,
		ServerKeyPEM:      keyPEM,
		RequireClientCert: false,
	}

	b, _ := createBackendWithSysView(t)

	srv, err := newTransitKmipServer(cfg, b)
	require.NoError(t, err)
	srv.Start()
	t.Cleanup(func() { _ = srv.Stop() })

	// Build a TLS client that trusts our self-signed server cert
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(certPEM))

	tlsCfg := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test-kmip",
	}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestKmipServer_RejectsInvalidClientCert(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCAWithKey(t)
	addr := freePort(t)

	cfg := &kmipConfig{
		Enabled:           true,
		ListenAddr:        addr,
		ServerCertPEM:     caCertPEM,
		ServerKeyPEM:      caKeyPEM,
		TLSCACertPEM:      caCertPEM,
		RequireClientCert: true,
	}

	b, _ := createBackendWithSysView(t)

	srv, err := newTransitKmipServer(cfg, b)
	require.NoError(t, err)
	srv.Start()
	t.Cleanup(func() { _ = srv.Stop() })

	// Connect without a client cert - should fail TLS handshake.
	// Force TLS 1.2 so that client cert verification is synchronous.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(caCertPEM))

	tlsCfg := &tls.Config{
		RootCAs:    certPool,
		ServerName: "test-kmip-ca",
		MaxVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err == nil {
		// Try to read to force server to process the (empty) client cert
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		_ = conn.Close()
	}
	require.Error(t, err, "connection without client cert should fail")
}

func TestKmipServer_LifecycleViaBackend(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, keyPEM := generateTestCert(t)
	addr := freePort(t)

	// Enable KMIP server via config write
	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled":             true,
			"listen_addr":         addr,
			"server_cert_pem":     certPEM,
			"server_key_pem":      keyPEM,
			"require_client_cert": false,
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Server should now be running
	b.kmipMu.Lock()
	require.NotNil(t, b.kmipServer, "KMIP server should be running after config write")
	b.kmipMu.Unlock()

	// Disable KMIP server
	disableReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled": false,
		},
	}
	resp, err = b.HandleRequest(context.Background(), disableReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Server should now be stopped
	b.kmipMu.Lock()
	require.Nil(t, b.kmipServer, "KMIP server should be stopped after disabling")
	b.kmipMu.Unlock()
}

func TestKmipServer_Cleanup(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, keyPEM := generateTestCert(t)
	addr := freePort(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled":             true,
			"listen_addr":         addr,
			"server_cert_pem":     certPEM,
			"server_key_pem":      keyPEM,
			"require_client_cert": false,
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	b.kmipMu.Lock()
	require.NotNil(t, b.kmipServer)
	b.kmipMu.Unlock()

	// Trigger cleanup (simulates vault unloading the backend)
	b.Cleanup(context.Background())

	b.kmipMu.Lock()
	require.Nil(t, b.kmipServer, "KMIP server should be nil after cleanup")
	b.kmipMu.Unlock()
}
