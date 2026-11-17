// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	kmipwrapper "github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
)

// The KMIP seal wrapper is a client of kmip-go, and its module pins an older
// release than the one this module selects for the listener. This runs the
// wrapper, as built here, against a kmip-go server that answers as a KMIP 1.4
// server does for an AES key.
func TestSealWrapperWithSelectedKMIPGo(t *testing.T) {
	pki := newPKI(t)
	cert, err := tls.X509KeyPair(pki.server.Pem, pki.server.PrivKey.Pem)
	require.NoError(t, err)
	clientCAs := x509.NewCertPool()
	require.True(t, clientCAs.AppendCertsFromPEM(pki.ca.Pem))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	exec := kmipserver.NewBatchExecutor()
	exec.Route(kmiplib.OperationGetAttributes, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
			return &payloads.GetAttributesResponsePayload{
				UniqueIdentifier: req.UniqueIdentifier,
				Attribute: []kmiplib.Attribute{
					{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: kmiplib.ObjectTypeSymmetricKey},
					{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: kmiplib.CryptographicAlgorithmAES},
					{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt | kmiplib.CryptographicUsageDecrypt},
				},
			}, nil
		}))
	exec.Route(kmiplib.OperationEncrypt, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
			sealed := gcm.Seal(nil, req.IVCounterNonce, req.Data, nil)
			n := len(sealed) - gcm.Overhead()
			return &payloads.EncryptResponsePayload{
				UniqueIdentifier:           req.UniqueIdentifier,
				Data:                       sealed[:n],
				AuthenticatedEncryptionTag: sealed[n:],
			}, nil
		}))
	exec.Route(kmiplib.OperationDecrypt, kmipserver.HandleFunc(
		func(_ context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
			sealed := append(append([]byte{}, req.Data...), req.AuthenticatedEncryptionTag...)
			plaintext, err := gcm.Open(nil, req.IVCounterNonce, sealed, nil)
			if err != nil {
				return nil, err
			}
			return &payloads.DecryptResponsePayload{UniqueIdentifier: req.UniqueIdentifier, Data: plaintext}, nil
		}))
	srv := kmipserver.NewServer(ln, exec)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	dir := t.TempDir()
	files := map[string][]byte{"ca.pem": pki.ca.Pem, "client.pem": pki.client.Pem, "client-key.pem": pki.client.PrivKey.Pem}
	for name, pem := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), pem, 0o600))
	}

	w := kmipwrapper.NewWrapper()
	_, err = w.SetConfig(t.Context(),
		wrapping.WithDisallowEnvVars(true),
		wrapping.WithKeyId("seal-key"),
		wrapping.WithConfigMap(map[string]string{
			"endpoint":    ln.Addr().String(),
			"ca_cert":     filepath.Join(dir, "ca.pem"),
			"client_cert": filepath.Join(dir, "client.pem"),
			"client_key":  filepath.Join(dir, "client-key.pem"),
			"server_name": "localhost",
			"encrypt_alg": "AES_GCM",
		}),
	)
	require.NoError(t, err)

	blob, err := w.Encrypt(t.Context(), []byte("root key"))
	require.NoError(t, err)
	require.NotContains(t, string(blob.Ciphertext), "root key")
	plaintext, err := w.Decrypt(t.Context(), blob)
	require.NoError(t, err)
	require.Equal(t, []byte("root key"), plaintext)
}
