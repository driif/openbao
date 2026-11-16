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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/forwarding"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
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
		verifyKMIPAudit(t, c, pki, pki.rawDialer(addr), auditLog, "app-active")

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
		client := pki.dial(t, addr, pki.client)
		_, err := client.Query().Exec()
		require.NoError(t, err)
		// With standby reads, the standby has an audit broker: it audits the
		// operation itself and forwards the transit writes.
		_, err = client.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-standby").Exec()
		require.NoError(t, err)
		// Forwarded HTTP denials still carry their server-generated request IDs.
		ctx, ids := forwarding.WithRequestIDs(t.Context())
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/transit/keys/other", nil)
		req.Header.Set("X-Vault-Token", "invalid-test-token")
		recorder := httptest.NewRecorder()
		vaulthttp.Handler.Handler(&vault.HandlerProperties{Core: standbys[0].Core}).ServeHTTP(recorder, req)
		require.Equal(t, http.StatusForbidden, recorder.Code)
		require.NotEmpty(t, ids.Values())
		raw, err := os.ReadFile(auditLog)
		require.NoError(t, err)
		for _, id := range ids.Values() {
			require.Contains(t, string(raw), id)
		}
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

	// ModifyAttribute replaces an instance; DeleteAttribute removes it.
	modified, err := c.ModifyAttribute(successor, "x-owner", "platform-team").Exec()
	require.NoError(t, err)
	require.Nil(t, modified.Attribute.AttributeIndex)
	owner, err = c.GetAttributes(successor, "x-owner").Exec()
	require.NoError(t, err)
	require.Len(t, owner.Attribute, 1)
	require.Equal(t, "platform-team", owner.Attribute[0].AttributeValue.(ttlv.Value).Value)
	_, err = c.DeleteAttribute(successor, "x-owner").Exec()
	require.NoError(t, err)
	owner, err = c.GetAttributes(successor, "x-owner").Exec()
	require.NoError(t, err)
	require.Empty(t, owner.Attribute)
	_, err = c.DeleteAttribute(successor, kmiplib.AttributeNameState).Exec()
	require.ErrorContains(t, err, "PermissionDenied")

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

	// Destroy refuses an Active key, even with deletion_allowed set. After a
	// compromise Revoke it marks the key Destroyed Compromised and keeps it.
	_, err = admin.Logical().Write("transit/keys/"+importedName+"/config", map[string]any{"deletion_allowed": true})
	require.NoError(t, err)
	_, err = c.Destroy(importedName).Exec()
	require.ErrorContains(t, err, "wrong key lifecycle state")
	_, err = c.Revoke(importedName).WithRevocationReasonCode(kmiplib.RevocationReasonCodeKeyCompromise).Exec()
	require.NoError(t, err)
	_, err = c.Destroy(importedName).Exec()
	require.NoError(t, err)
	destroyed, err := c.GetAttributes(importedName, kmiplib.AttributeNameState, kmiplib.AttributeNameDestroyDate, kmiplib.AttributeNameRevocationReason).Exec()
	require.NoError(t, err)
	require.Len(t, destroyed.Attribute, 3)
	require.Equal(t, kmiplib.StateDestroyedCompromised, destroyed.Attribute[0].AttributeValue)
	require.Equal(t, kmiplib.RevocationReasonCodeKeyCompromise, destroyed.Attribute[2].AttributeValue.(kmiplib.RevocationReason).RevocationReasonCode)
	_, err = c.Get(importedName).Exec()
	require.ErrorContains(t, err, "wrong key lifecycle state")
	kept, err := admin.Logical().Read("transit/keys/" + importedName)
	require.NoError(t, err)
	require.NotNil(t, kept)
	require.Equal(t, true, kept.Data["soft_deleted"])
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

	return serveKMIPListener(t, core, authMount, ln)
}

func serveKMIPListener(t *testing.T, core *vault.TestClusterCore, authMount string, ln net.Listener) string {
	t.Helper()
	handler := vaulthttp.Handler.Handler(&vault.HandlerProperties{
		Core: core.Core,
		ListenerConfig: &configutil.Listener{
			Type:      "kmip",
			Address:   ln.Addr().String(),
			AuthMount: authMount,
		},
	})
	srv, err := kmip.NewServer(ln, handler, kmip.Config{AuthMount: authMount, Auditor: core.Core, Metrics: core.MetricSink()})
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

// rawDialer returns a function that opens a TLS connection to addr as p's
// client, for frames that kmipclient cannot send.
func (p testPKI) rawDialer(addr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(p.ca.Pem)
		d := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{p.client.TLSCert}, MinVersion: tls.VersionTLS12}}
		return d.DialContext(ctx, "tcp", addr)
	}
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

// A standby without standby reads has no audit broker, so it answers only
// Query and DiscoverVersions and refuses everything else.
func TestKMIPListenerStandbyWithoutBroker(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{"cert": cert.Factory},
		LogicalBackends:    map[string]logical.Factory{"transit": transit.Factory},
		AuditBackends:      map[string]audit.Factory{"file": auditFile.Factory},
	}, &vault.TestClusterOptions{
		HandlerFunc:         vaulthttp.Handler,
		NumCores:            2,
		DisableStandbyReads: true,
	})
	cluster.Start()
	t.Cleanup(cluster.Cleanup)
	testhelpers.WaitForActiveNodeAndStandbys(t, cluster)

	active := testhelpers.DeriveActiveCore(t, cluster)
	standbys := testhelpers.DeriveStandbyCores(t, cluster)
	require.NotEmpty(t, standbys)
	require.NoError(t, active.Client.Sys().EnableAuditWithOptions("file", &api.EnableAuditOptions{
		Type:    "file",
		Options: map[string]string{"file_path": filepath.Join(t.TempDir(), "audit.log")},
	}))
	pki := newPKI(t)
	setUpTenant(t, active.Client, pki)

	client := pki.dial(t, serveKMIP(t, standbys[0], "auth/cert", pki), pki.client)
	_, err := client.Query().Exec()
	require.NoError(t, err)
	_, err = client.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-standby").Exec()
	require.ErrorContains(t, err, "standby has no audit broker")
}

// A connected client must see the sealed refusal. The same listener must work
// again after unsealing, without a restart or a cached audit broker.
func TestKMIPListenerSealRecovery(t *testing.T) {
	core, keys, rootToken := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		RawConfig:          &server.Config{SharedConfig: &configutil.SharedConfig{}, UnsafeAllowAPIAuditCreation: true},
		CredentialBackends: map[string]logical.Factory{"cert": cert.Factory},
		LogicalBackends:    map[string]logical.Factory{"transit": transit.Factory},
		AuditBackends:      map[string]audit.Factory{"file": auditFile.Factory},
	})
	t.Cleanup(func() { _ = core.Shutdown() })
	handler := vaulthttp.Handler.Handler(&vault.HandlerProperties{Core: core})
	admin, err := api.NewClient(&api.Config{Address: "http://memory", HttpClient: &http.Client{Transport: directHTTP{handler}}})
	require.NoError(t, err)
	admin.SetToken(rootToken)
	active := &vault.TestClusterCore{Core: core, Client: admin}
	auditLog := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, active.Client.Sys().EnableAuditWithOptions("file", &api.EnableAuditOptions{Type: "file", Options: map[string]string{"file_path": auditLog}}))
	pki := newPKI(t)
	setUpTenant(t, active.Client, pki)
	ln := newSealListener(t, pki)
	serveKMIPListener(t, active, "auth/cert", ln)
	client := ln.client(t, pki)
	_, err = client.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-seal").Exec()
	require.NoError(t, err)
	require.NoError(t, vault.TestCoreSeal(active.Core))
	_, err = client.Get("app-seal").Exec()
	require.ErrorContains(t, err, "store is sealed")
	for _, key := range keys {
		_, err = core.Unseal(key)
		require.NoError(t, err)
	}
	require.False(t, core.Sealed())
	recovered := ln.client(t, pki)
	_, err = recovered.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-unsealed").Exec()
	require.NoError(t, err)
	exercise(t, recovered, admin, "app-pipe")
	verifyKMIPAudit(t, recovered, pki, func(ctx context.Context) (net.Conn, error) { return ln.dial(ctx, pki) }, auditLog, "app-unsealed")
}

func verifyKMIPAudit(t *testing.T, client *kmipclient.Client, pki testPKI, dial func(context.Context) (net.Conn, error), file, prefix string) {
	t.Helper()

	// Create, Get, Encrypt, a Destroy refused for its state, Query, and a
	// malformed Get on a connection of its own.
	created, err := client.Create().AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).WithName(prefix + "-audit").Exec()
	require.NoError(t, err)
	uid := created.UniqueIdentifier
	got, err := client.Get(uid).Exec()
	require.NoError(t, err)
	key, ok := got.Object.(*kmiplib.SymmetricKey)
	require.True(t, ok, "Get returned %T", got.Object)
	exported, err := key.KeyBlock.GetBytes()
	require.NoError(t, err)
	plaintext := []byte("audited plaintext of " + prefix)
	enc, err := client.Encrypt(uid).Data(plaintext).Exec()
	require.NoError(t, err)
	_, err = client.Destroy(uid).Exec()
	require.ErrorContains(t, err, "wrong key lifecycle state")
	_, err = client.Query().Exec()
	require.NoError(t, err)
	malformed := sendMalformedGet(t, dial, uid)
	require.Equal(t, kmiplib.ResultReasonInvalidMessage, malformed.ResultReason)

	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	for _, secret := range [][]byte{exported, plaintext, enc.Data} {
		for _, value := range []string{string(secret), base64.StdEncoding.EncodeToString(secret), hex.EncodeToString(secret)} {
			require.NotContains(t, string(raw), value)
		}
	}

	type record struct {
		Type    string         `json:"type"`
		Auth    map[string]any `json:"auth"`
		Request struct {
			ID     string         `json:"id"`
			Data   map[string]any `json:"data"`
			Serial string         `json:"client_certificate_serial_number"`
		} `json:"request"`
		Response struct {
			Data map[string]any `json:"data"`
		} `json:"response"`
	}
	type pair struct{ request, response *record }
	pairs := map[string]*pair{}
	transit := map[string]bool{}
	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		entry := new(record)
		if json.Unmarshal(line, entry) != nil {
			continue
		}
		if _, ok := entry.Request.Data["kmip_operation"]; !ok {
			transit[entry.Request.ID] = true
			continue
		}
		require.NotEmpty(t, entry.Request.ID)
		p := pairs[entry.Request.ID]
		if p == nil {
			p = new(pair)
			pairs[entry.Request.ID] = p
		}
		if entry.Type == "request" {
			require.Nil(t, p.request, "two request entries for %s", entry.Request.ID)
			p.request = entry
		} else {
			require.Nil(t, p.response, "two response entries for %s", entry.Request.ID)
			p.response = entry
		}
	}

	clientCert, err := x509.ParseCertificate(pki.client.RawCert)
	require.NoError(t, err)
	find := func(op, outcome string, match func(*pair) bool) *pair {
		t.Helper()
		var found *pair
		for id, p := range pairs {
			require.NotNil(t, p.request, "no request entry for %s", id)
			require.NotNil(t, p.response, "no response entry for %s", id)
			if p.response.Response.Data["kmip_operation"] == op && p.response.Response.Data["outcome"] == outcome && match(p) {
				found = p
			}
		}
		require.NotNil(t, found, "no audit pair for %s with outcome %s", op, outcome)
		require.Equal(t, op, found.request.Request.Data["kmip_operation"])
		require.Equal(t, clientCert.Subject.String(), found.request.Request.Data["client_certificate_subject"])
		require.NotEmpty(t, found.request.Request.Serial)
		return found
	}
	hasUID := func(p *pair) bool { return p.response.Response.Data["unique_identifier"] == uid }
	linked := func(p *pair) {
		t.Helper()
		ids, _ := p.response.Response.Data["transit_request_ids"].([]any)
		require.NotEmpty(t, ids, p.request.Request.Data["kmip_operation"])
		for _, id := range ids {
			require.True(t, transit[id.(string)], id)
		}
	}
	loggedIn := func(p *pair) {
		t.Helper()
		require.NotEmpty(t, p.request.Auth["accessor"])
		require.Contains(t, p.request.Auth["token_policies"], "kmip-app")
	}

	for _, op := range []string{"Create", "Get", "Encrypt"} {
		p := find(op, "success", hasUID)
		loggedIn(p)
		linked(p)
	}
	loggedIn(find("Destroy", "PermissionDenied", hasUID))
	// A Query can be the first operation of a connection, before login, so
	// only its certificate identity is checked.
	find("Query", "success", func(*pair) bool { return true })
	// The malformed Get keeps its operation name; its payload, and so its
	// identifier, is never read.
	find("Get", "InvalidMessage", func(p *pair) bool { return p.request.Request.Data["unique_identifier"] == nil })
}

// sendMalformedGet sends a Get for uid whose Unique Identifier is encoded as
// an Integer, on a new connection, and returns the reply's batch item.
func sendMalformedGet(t *testing.T, dial func(context.Context) (net.Conn, error), uid string) kmiplib.ResponseBatchItem {
	t.Helper()
	conn, err := dial(t.Context())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	frame := ttlv.MarshalTTLV(&kmiplib.RequestMessage{
		Header:    kmiplib.RequestHeader{ProtocolVersion: kmiplib.V1_4, BatchCount: 1},
		BatchItem: []kmiplib.RequestBatchItem{{Operation: kmiplib.OperationGet, RequestPayload: &payloads.GetRequestPayload{UniqueIdentifier: uid}}},
	})
	at := bytes.Index(frame, []byte{0x42, 0x00, 0x94, byte(ttlv.TypeTextString)})
	require.Positive(t, at)
	frame[at+3] = byte(ttlv.TypeInteger)
	_, err = conn.Write(frame)
	require.NoError(t, err)
	var resp kmiplib.ResponseMessage
	stream := ttlv.NewStream(conn, 1<<20)
	require.NoError(t, stream.Recv(&resp))
	require.Len(t, resp.BatchItem, 1)
	return resp.BatchItem[0]
}

// directHTTP keeps the integration path through the real HTTP handler while
// avoiding a TCP listener for the admin client.
type directHTTP struct{ handler http.Handler }

func (d directHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil {
		req.Body = http.NoBody
	}
	recorder := httptest.NewRecorder()
	d.handler.ServeHTTP(recorder, req)
	resp := recorder.Result()
	resp.Request = req
	return resp, nil
}

type sealListener struct {
	conns    chan net.Conn
	done     chan struct{}
	once     sync.Once
	sequence atomic.Int32
	cfg      *tls.Config
}
type sealPeer struct {
	net.Conn
	addr net.Addr
}

func (c *sealPeer) RemoteAddr() net.Addr { return c.addr }
func (l *sealListener) Addr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5696} }
func (l *sealListener) Close() error     { l.once.Do(func() { close(l.done) }); return nil }
func (l *sealListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func newSealListener(t *testing.T, p testPKI) *sealListener {
	t.Helper()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(p.ca.Pem))
	l := &sealListener{conns: make(chan net.Conn), done: make(chan struct{}), cfg: &tls.Config{Certificates: []tls.Certificate{p.server.TLSCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func (l *sealListener) client(t *testing.T, p testPKI) *kmipclient.Client {
	t.Helper()
	c, err := kmipclient.Dial("memory", kmipclient.WithDialerUnsafe(func(ctx context.Context, _ string) (net.Conn, error) {
		return l.dial(ctx, p)
	}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// dial opens a TLS connection to the listener as p's client.
func (l *sealListener) dial(ctx context.Context, p testPKI) (net.Conn, error) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(p.ca.Pem)
	server, client := net.Pipe()
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(l.sequence.Add(1)) + 10000}
	server = &sealPeer{Conn: server, addr: remote}
	select {
	case l.conns <- tls.Server(server, l.cfg):
		conn := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{p.client.TLSCert}, MinVersion: tls.VersionTLS12})
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	case <-ctx.Done():
		_ = server.Close()
		_ = client.Close()
		return nil, ctx.Err()
	}
}
