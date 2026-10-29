// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/audit"
	auditFile "github.com/openbao/openbao/v2/internal/builtin/audit/file"
	"github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	"github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/certhelpers"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/kmip"
	"github.com/openbao/openbao/v2/internal/vault"
)

// appPolicy lets a KMIP client use transit keys named app-*, and nothing
// else on the mount.
const appPolicy = `
path "transit/keys" {
  capabilities = ["list"]
}
path "transit/keys/app-*" {
  capabilities = ["read", "update", "delete"]
}
path "transit/wrapping_key" {
  capabilities = ["read"]
}
path "transit/export/+/app-*" {
  capabilities = ["read"]
}
path "transit/encrypt/app-*" {
  capabilities = ["update"]
}
path "transit/decrypt/app-*" {
  capabilities = ["update"]
}
path "transit/sign/app-*" {
  capabilities = ["update"]
}
path "transit/verify/app-*" {
  capabilities = ["update"]
}
`

// TestKMIPListener drives a KMIP client through a kmip listener on an
// active node, on a standby that forwards to it, and into a namespace.
func TestKMIPListener(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{"cert": cert.Factory},
		LogicalBackends:    map[string]logical.Factory{"transit": transit.Factory},
		AuditBackends:      map[string]audit.Factory{"file": auditFile.Factory},
	}, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    2,
	})
	cluster.Start()
	t.Cleanup(cluster.Cleanup)
	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	active := testhelpers.DeriveActiveCore(t, cluster)
	standbys := testhelpers.DeriveStandbyCores(t, cluster)
	require.NotEmpty(t, standbys)
	root := active.Client

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, root.Sys().EnableAuditWithOptions("file", &api.EnableAuditOptions{
		Type:    "file",
		Options: map[string]string{"file_path": auditLog},
	}))

	pki := newPKI(t)
	setUpTenant(t, root, pki)
	_, err := root.Logical().Write("sys/namespaces/ns1", nil)
	require.NoError(t, err)
	setUpTenant(t, root.WithNamespace("ns1"), pki)

	t.Run("active", func(t *testing.T) {
		addr := serveKMIP(t, active, "auth/cert", pki)
		c := pki.dial(t, addr, pki.client)
		exercise(t, c, root, "app-active")

		// Operations reach the audit log as the client's own requests.
		paths, err := auditedPaths(auditLog)
		require.NoError(t, err)
		require.Contains(t, paths, "transit/encrypt/app-active-aes")
		require.Contains(t, paths, "transit/keys/app-active-imported/import")
		require.Contains(t, paths, "transit/keys/app-active-rekey/metadata")
		require.Contains(t, paths, "transit/keys/app-active-rekey.2/metadata")

		// Closing the connection revokes the session's token.
		revocations := countOf(paths, "auth/token/revoke-self")
		require.NoError(t, c.Close())
		require.Eventually(t, func() bool {
			paths, err := auditedPaths(auditLog)
			return err == nil && countOf(paths, "auth/token/revoke-self") > revocations
		}, 10*time.Second, 50*time.Millisecond)

		// A certificate from the same CA that matches no cert role cannot log in.
		intruder := certhelpers.NewCert(t, certhelpers.CommonName("intruder"), certhelpers.Parent(pki.ca))
		_, err = pki.dial(t, addr, intruder).Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-intruder").Exec()
		require.ErrorContains(t, err, "login through auth/cert/login failed")
	})

	t.Run("standby", func(t *testing.T) {
		addr := serveKMIP(t, standbys[0], "auth/cert", pki)
		exercise(t, pki.dial(t, addr, pki.client), root, "app-standby")
	})

	t.Run("namespace", func(t *testing.T) {
		addr := serveKMIP(t, active, "ns1/auth/cert", pki)
		exercise(t, pki.dial(t, addr, pki.client), root.WithNamespace("ns1"), "app-ns")
	})
}

// exercise runs every supported KMIP operation on keys named prefix-*,
// using admin to change what KMIP cannot.
func exercise(t *testing.T, c *kmipclient.Client, admin *api.Client, prefix string) {
	t.Helper()

	query, err := c.Query().Operations().Objects().ServerInformation().Exec()
	require.NoError(t, err)
	require.Contains(t, query.Operations, kmiplib.OperationCreate)

	aesName := prefix + "-aes"
	created, err := c.Create().
		AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).
		WithName(aesName).
		Exec()
	require.NoError(t, err)
	require.Equal(t, aesName, created.UniqueIdentifier)

	// A nameless key is named after the cert role's kmip_key_prefix.
	nameless, err := c.Create().AES(128, kmiplib.CryptographicUsageEncrypt).Exec()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(nameless.UniqueIdentifier, "app-"), nameless.UniqueIdentifier)

	enc, err := c.Encrypt(aesName).Data([]byte("kmip payload")).Exec()
	require.NoError(t, err)
	dec, err := c.Decrypt(aesName).Data(enc.Data).Exec()
	require.NoError(t, err)
	require.Equal(t, []byte("kmip payload"), dec.Data)

	// Registered material is wrapped for transit's import and comes back
	// unchanged from Get.
	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)
	importedName := prefix + "-imported"
	_, err = c.Register().
		SymmetricKey(kmiplib.CryptographicAlgorithmAES, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt, material).
		WithName(importedName).
		Exec()
	require.NoError(t, err)
	got, err := c.Get(importedName).Exec()
	require.NoError(t, err)
	key, ok := got.Object.(*kmiplib.SymmetricKey)
	require.True(t, ok, "Get returned %T", got.Object)
	gotMaterial, err := key.KeyBlock.GetBytes()
	require.NoError(t, err)
	require.Equal(t, material, gotMaterial)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaName := prefix + "-rsa"
	_, err = c.Register().
		WithKeyFormat(kmipclient.PKCS8).
		RsaPrivateKey(priv, kmiplib.CryptographicUsageSign|kmiplib.CryptographicUsageVerify).
		WithName(rsaName).
		Exec()
	require.NoError(t, err)
	signed, err := c.Sign(rsaName).Data([]byte("signed data")).Exec()
	require.NoError(t, err)
	verified, err := c.SignatureVerify(rsaName).Data([]byte("signed data")).Signature(signed.SignatureData).Exec()
	require.NoError(t, err)
	require.Equal(t, kmiplib.ValidityIndicatorValid, verified.ValidityIndicator)

	byName, err := c.Locate().WithName(aesName).Exec()
	require.NoError(t, err)
	require.Equal(t, []string{aesName}, byName.UniqueIdentifier)

	// Attributes are stored, listed and returned; ReKey hands the Name to a
	// replacement and keeps the predecessor readable.
	rekeyName := prefix + "-rekey"
	_, err = c.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName(rekeyName).Exec()
	require.NoError(t, err)
	_, err = c.AddAttribute(rekeyName, "x-owner", "storage-team").Exec()
	require.NoError(t, err)
	list, err := c.GetAttributeList(rekeyName).Exec()
	require.NoError(t, err)
	require.Contains(t, list.AttributeName, kmiplib.AttributeName("x-owner"))
	owner, err := c.GetAttributes(rekeyName, "x-owner").Exec()
	require.NoError(t, err)
	require.Len(t, owner.Attribute, 1)
	require.Equal(t, "storage-team", owner.Attribute[0].AttributeValue.(ttlv.Value).Value)

	rekeyed, err := c.Rekey(rekeyName).Exec()
	require.NoError(t, err)
	successor := rekeyName + ".2"
	require.Equal(t, successor, rekeyed.UniqueIdentifier)
	for _, uid := range []string{successor, rekeyName} {
		_, err = c.Get(uid).Exec()
		require.NoError(t, err, uid)
	}
	state, err := c.GetAttributes(rekeyName, kmiplib.AttributeNameState).Exec()
	require.NoError(t, err)
	require.Equal(t, kmiplib.StateDeactivated, state.Attribute[0].AttributeValue)
	owner, err = c.GetAttributes(successor, "x-owner", kmiplib.AttributeNameName).Exec()
	require.NoError(t, err)
	require.Len(t, owner.Attribute, 2)
	byRekeyedName, err := c.Locate().WithName(rekeyName).Exec()
	require.NoError(t, err)
	require.Equal(t, []string{successor}, byRekeyedName.UniqueIdentifier)

	// Locate skips the key the policy hides, and Get is refused it.
	symmetric, err := c.Locate().WithObjectType(kmiplib.ObjectTypeSymmetricKey).Exec()
	require.NoError(t, err)
	require.Contains(t, symmetric.UniqueIdentifier, aesName)
	require.Contains(t, symmetric.UniqueIdentifier, importedName)
	require.NotContains(t, symmetric.UniqueIdentifier, "other")
	_, err = c.Get("other").Exec()
	require.ErrorContains(t, err, "permission denied")

	// A soft-deleted key is Deactivated, and its material is withheld.
	_, err = admin.Logical().Delete("transit/keys/" + aesName + "/soft-delete")
	require.NoError(t, err)
	attrs, err := c.GetAttributes(aesName).WithAttributes(kmiplib.AttributeNameState).Exec()
	require.NoError(t, err)
	require.Len(t, attrs.Attribute, 1)
	require.Equal(t, kmiplib.StateDeactivated, attrs.Attribute[0].AttributeValue)
	_, err = c.Get(aesName).Exec()
	require.ErrorContains(t, err, "wrong key lifecycle state")
	_, err = c.Activate(aesName).ExecContext(t.Context())
	require.ErrorContains(t, err, "wrong key lifecycle state")

	// Destroy waits for deletion_allowed.
	_, err = c.Destroy(importedName).Exec()
	require.ErrorContains(t, err, "deletion_allowed")
	_, err = admin.Logical().Write("transit/keys/"+importedName+"/config", map[string]any{"deletion_allowed": true})
	require.NoError(t, err)
	_, err = c.Destroy(importedName).Exec()
	require.NoError(t, err)
	_, err = c.Get(importedName).Exec()
	require.ErrorContains(t, err, "not found")
}

// setUpTenant mounts transit and cert auth through client, with a cert role
// that routes the PKI's client to transit with prefix app-, and a key the
// role's policy does not cover.
func setUpTenant(t *testing.T, client *api.Client, pki testPKI) {
	t.Helper()

	require.NoError(t, client.Sys().Mount("transit", &api.MountInput{Type: "transit"}))
	require.NoError(t, client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{Type: "cert"}))
	require.NoError(t, client.Sys().PutPolicy("kmip-app", appPolicy))

	_, err := client.Logical().Write("auth/cert/certs/app", map[string]any{
		"certificate":          string(pki.ca.Pem),
		"allowed_common_names": "kmip-client",
		"token_policies":       "kmip-app",
		"kmip_transit_mount":   "transit",
		"kmip_key_prefix":      "app-",
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("transit/keys/other", map[string]any{"exportable": true})
	require.NoError(t, err)
}

// serveKMIP serves KMIP for core on a new TLS listener, the way the server
// command serves a kmip listener, and returns its address.
func serveKMIP(t *testing.T, core *vault.TestClusterCore, authMount string, pki testPKI) string {
	t.Helper()

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pki.ca.Pem))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.server.TLSCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)

	handler := vaulthttp.Handler.Handler(&vault.HandlerProperties{
		Core: core.Core,
		ListenerConfig: &configutil.Listener{
			Type:      "kmip",
			Address:   ln.Addr().String(),
			AuthMount: authMount,
		},
	})
	srv, err := kmip.NewServer(ln, handler, kmip.Config{AuthMount: authMount})
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, srv.Shutdown(ctx))
		require.NoError(t, <-served)
	})
	return ln.Addr().String()
}

type testPKI struct {
	ca     certhelpers.Certificate
	server certhelpers.Certificate
	client certhelpers.Certificate
}

func newPKI(t *testing.T) testPKI {
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

func (p testPKI) dial(t *testing.T, addr string, as certhelpers.Certificate) *kmipclient.Client {
	t.Helper()

	c, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(p.ca.Pem),
		kmipclient.WithServerName("localhost"),
		kmipclient.WithClientCertPEM(as.Pem, as.PrivKey.Pem),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// auditedPaths returns the path of every request in the audit log. A line
// still being written is skipped.
func auditedPaths(file string) ([]string, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var paths []string
	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		var entry struct {
			Type    string `json:"type"`
			Request struct {
				Path string `json:"path"`
			} `json:"request"`
		}
		if json.Unmarshal(line, &entry) == nil && entry.Type == "request" {
			paths = append(paths, entry.Request.Path)
		}
	}
	return paths, nil
}

func countOf(paths []string, path string) int {
	n := 0
	for _, p := range paths {
		if p == path {
			n++
		}
	}
	return n
}
