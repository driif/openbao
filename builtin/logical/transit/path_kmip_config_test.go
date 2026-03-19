// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// generateTestCert returns PEM-encoded self-signed cert and private key for testing.
func generateTestCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-kmip",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	var certBuf bytes.Buffer
	require.NoError(t, pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	var keyBuf bytes.Buffer
	require.NoError(t, pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	return certBuf.String(), keyBuf.String()
}

func TestKmipConfig_ReadEmpty(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "config/kmip",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestKmipConfig_WriteAndRead(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, keyPEM := generateTestCert(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled":             true,
			"listen_addr":         "127.0.0.1:5696",
			"server_cert_pem":     certPEM,
			"server_key_pem":      keyPEM,
			"tls_ca_cert_pem":     certPEM,
			"require_client_cert": true,
		},
	}

	resp, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "config/kmip",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, true, resp.Data["enabled"])
	require.Equal(t, "127.0.0.1:5696", resp.Data["listen_addr"])
	require.Equal(t, certPEM, resp.Data["server_cert_pem"])
	require.Equal(t, certPEM, resp.Data["tls_ca_cert_pem"])
	require.Equal(t, true, resp.Data["require_client_cert"])
	// Private key must not be returned
	_, hasKey := resp.Data["server_key_pem"]
	require.False(t, hasKey)
}

func TestKmipConfig_PartialUpdate(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, keyPEM := generateTestCert(t)

	// Write initial config
	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled":         false,
			"listen_addr":     "127.0.0.1:5696",
			"server_cert_pem": certPEM,
			"server_key_pem":  keyPEM,
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Update only listen_addr
	updateReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"listen_addr": "0.0.0.0:15696",
		},
	}
	resp, err := b.HandleRequest(context.Background(), updateReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "config/kmip",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, "0.0.0.0:15696", resp.Data["listen_addr"])
	// Original cert should still be there
	require.Equal(t, certPEM, resp.Data["server_cert_pem"])
}

// requireErrResponse asserts that a request returned either a non-nil error or
// an error response, which is how the framework surfaces logical.ErrInvalidRequest.
func requireErrResponse(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	if err != nil {
		return // error returned directly
	}
	require.NotNil(t, resp, "expected an error response but got nil")
	require.True(t, resp.IsError(), "expected resp.IsError() to be true")
}

func TestKmipConfig_InvalidCertKey(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, _ := generateTestCert(t)
	_, differentKey := generateTestCert(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"server_cert_pem": certPEM,
			"server_key_pem":  differentKey, // mismatched key
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	requireErrResponse(t, resp, err)
}

func TestKmipConfig_EnabledWithoutCert(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"enabled":     true,
			"listen_addr": "127.0.0.1:5696",
			// no cert/key provided
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	requireErrResponse(t, resp, err)
}

func TestKmipConfig_InvalidCACert(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	certPEM, keyPEM := generateTestCert(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Data: map[string]interface{}{
			"server_cert_pem": certPEM,
			"server_key_pem":  keyPEM,
			"tls_ca_cert_pem": "not-valid-pem",
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	requireErrResponse(t, resp, err)
}
