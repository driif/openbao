// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"
)

// dialKmipClient creates a kmipclient.Client that connects to the given address
// using the provided CA cert and (optional) client cert+key PEM.
func dialKmipClient(t *testing.T, addr, caCertPEM string, clientCertPEM, clientKeyPEM []byte) *kmipclient.Client {
	t.Helper()

	opts := []kmipclient.Option{
		kmipclient.WithRootCAPem([]byte(caCertPEM)),
		kmipclient.WithServerName("test-kmip-ca"),
	}
	if len(clientCertPEM) > 0 {
		opts = append(opts, kmipclient.WithClientCertPEM(clientCertPEM, clientKeyPEM))
	}

	c, err := kmipclient.Dial(addr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// subjectDNFromPEM parses a PEM-encoded certificate and returns its Subject.String().
func subjectDNFromPEM(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "failed to decode PEM block")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert.Subject.String()
}

// TestKmipIntegration_EndToEnd exercises the full KMIP server stack:
//   - Create, GetAttributes, Locate, Encrypt/Decrypt, Destroy operations
//   - Rejection of clients whose cert DN has no matching role
func TestKmipIntegration_EndToEnd(t *testing.T) {
	caCertPEM, caKeyPEM, caKey, caCertDER := generateTestCAWithKey(t)
	addr := freePort(t)

	b, storage := createBackendWithSysView(t)
	b.storage = storage
	ctx := context.Background()

	// Build a client certificate signed by the CA.
	clientDN := pkix.Name{CommonName: "integration-client", Organization: []string{"TestOrg"}}
	clientCertPEM, clientKey := generateClientCertWithDN(t, clientDN, caKey, caCertDER)
	clientKeyPEM := ecKeyToPEM(t, clientKey)

	// Register a role that allows all operations with any key.
	role := &kmipRole{
		CertSubjectDN:     subjectDNFromPEM(t, clientCertPEM),
		AllowedOperations: nil, // nil = allow all
		AllowedKeyNames:   nil,
	}
	require.NoError(t, b.putKmipRole(ctx, storage, "integration-client", role))

	// Start the KMIP server.
	cfg := &kmipConfig{
		Enabled:           true,
		ListenAddr:        addr,
		ServerCertPEM:     caCertPEM,
		ServerKeyPEM:      caKeyPEM,
		TLSCACertPEM:      caCertPEM,
		RequireClientCert: true,
	}
	srv, err := newTransitKmipServer(cfg, b)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Stop() })

	// Connect the authorised client.
	client := dialKmipClient(t, addr, caCertPEM, []byte(clientCertPEM), clientKeyPEM)

	// --- Create ---
	keyName := "integ-aes-key"
	createResp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName(keyName).
		Exec()
	require.NoError(t, err, "Create should succeed")
	require.Equal(t, keyName, createResp.UniqueIdentifier)

	// --- GetAttributes ---
	attrResp, err := client.GetAttributes(keyName,
		kmip.AttributeNameCryptographicAlgorithm,
		kmip.AttributeNameCryptographicLength,
	).Exec()
	require.NoError(t, err, "GetAttributes should succeed")
	require.Equal(t, keyName, attrResp.UniqueIdentifier)
	require.NotEmpty(t, attrResp.Attribute, "should have at least one attribute")

	// --- Locate ---
	locateResp, err := client.Locate().Exec()
	require.NoError(t, err, "Locate should succeed")
	require.Contains(t, locateResp.UniqueIdentifier, keyName, "Locate should list the created key")

	// --- Encrypt ---
	plaintext := []byte("hello, kmip world!")
	encResp, err := client.Encrypt(keyName).Data(plaintext).Exec()
	require.NoError(t, err, "Encrypt should succeed")
	require.NotEmpty(t, encResp.Data, "encrypted data should not be empty")

	// --- Decrypt ---
	decResp, err := client.Decrypt(keyName).Data(encResp.Data).Exec()
	require.NoError(t, err, "Decrypt should succeed")
	require.Equal(t, plaintext, decResp.Data, "decrypted data should match original plaintext")

	// --- Destroy ---
	destroyResp, err := client.Destroy(keyName).Exec()
	require.NoError(t, err, "Destroy should succeed")
	require.Equal(t, keyName, destroyResp.UniqueIdentifier)
}

// TestKmipIntegration_UnknownClientRejected verifies that a KMIP client whose
// certificate Subject DN has no matching role is rejected by the auth middleware.
func TestKmipIntegration_UnknownClientRejected(t *testing.T) {
	caCertPEM, caKeyPEM, caKey, caCertDER := generateTestCAWithKey(t)
	addr := freePort(t)

	b, storage := createBackendWithSysView(t)
	b.storage = storage
	ctx := context.Background()

	// Register a role only for "known-client".
	knownDN := pkix.Name{CommonName: "known-client", Organization: []string{"TestOrg"}}
	knownCertPEM, knownKey := generateClientCertWithDN(t, knownDN, caKey, caCertDER)
	knownRole := &kmipRole{
		CertSubjectDN:     subjectDNFromPEM(t, knownCertPEM),
		AllowedOperations: nil,
		AllowedKeyNames:   nil,
	}
	require.NoError(t, b.putKmipRole(ctx, storage, "known-client", knownRole))

	// Start the KMIP server.
	cfg := &kmipConfig{
		Enabled:           true,
		ListenAddr:        addr,
		ServerCertPEM:     caCertPEM,
		ServerKeyPEM:      caKeyPEM,
		TLSCACertPEM:      caCertPEM,
		RequireClientCert: true,
	}
	srv, err := newTransitKmipServer(cfg, b)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Stop() })

	// The known client should succeed.
	knownKeyPEM := ecKeyToPEM(t, knownKey)
	knownClient := dialKmipClient(t, addr, caCertPEM, []byte(knownCertPEM), knownKeyPEM)
	_, err = knownClient.Create().AES(256, kmip.CryptographicUsageEncrypt).
		WithName("known-key").Exec()
	require.NoError(t, err, "known client should be allowed to Create")

	// Connect with the unknown client cert.
	unknownDN := pkix.Name{CommonName: "unknown-client", Organization: []string{"TestOrg"}}
	unknownCertPEM, unknownKey := generateClientCertWithDN(t, unknownDN, caKey, caCertDER)
	unknownKeyPEM := ecKeyToPEM(t, unknownKey)

	// The unknown client TLS handshake succeeds (cert is CA-signed) but the
	// KMIP auth middleware rejects the DiscoverVersions request sent during
	// connection negotiation, causing Dial itself to return an error.
	_, err = kmipclient.Dial(addr,
		kmipclient.WithRootCAPem([]byte(caCertPEM)),
		kmipclient.WithServerName("test-kmip-ca"),
		kmipclient.WithClientCertPEM([]byte(unknownCertPEM), unknownKeyPEM),
	)
	require.Error(t, err, "unknown client should be rejected by auth middleware during negotiation")
}
