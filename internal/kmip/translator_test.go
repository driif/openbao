// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/logical/transit"
)

const (
	testLoginPath  = "auth/cert/login"
	testRevokePath = "auth/token/revoke-self"
	testRemoteAddr = "192.0.2.10:40000"
)

var testPeer = &x509.Certificate{Subject: pkix.Name{CommonName: "kmip-client"}}

// fakeBao stands in for the OpenBao HTTP handler. It records every request
// and answers from routes keyed by method and path, the path relative to
// /v1/. Without a route, logins hand out numbered tokens, revoke-self
// succeeds, and anything else goes to fallback or is a 404.
type fakeBao struct {
	t *testing.T

	mu       sync.Mutex
	routes   map[string]fakeRoute
	fallback fakeRoute
	requests []fakeRequest
	logins   int

	leaseSeconds int
	tokenType    string
	metadata     map[string]string
}

type fakeRoute func(r fakeRequest) (status int, body any)

type fakeRequest struct {
	method     string
	path       string
	query      url.Values
	token      string
	namespace  string
	body       map[string]any
	peerCerts  []*x509.Certificate
	remoteAddr string
	ctxErr     error
}

func newFakeBao(t *testing.T) *fakeBao {
	return &fakeBao{
		t:            t,
		routes:       map[string]fakeRoute{},
		leaseSeconds: 3600,
		tokenType:    "service",
		metadata: map[string]string{
			"cert_name":          "app",
			"kmip_transit_mount": "transit",
			"kmip_key_prefix":    "app-",
		},
	}
}

func (f *fakeBao) route(method, path string, r fakeRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = r
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := fakeRequest{
		method:     r.Method,
		path:       strings.TrimPrefix(r.URL.Path, "/v1/"),
		query:      r.URL.Query(),
		token:      r.Header.Get(consts.AuthHeaderName),
		namespace:  r.Header.Get(consts.NamespaceHeaderName),
		remoteAddr: r.RemoteAddr,
		ctxErr:     r.Context().Err(),
	}
	if r.TLS != nil {
		req.peerCerts = r.TLS.PeerCertificates
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("reading request body: %v", err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req.body); err != nil {
			f.t.Errorf("decoding request body %q: %v", raw, err)
		}
	}

	f.mu.Lock()
	f.requests = append(f.requests, req)
	route, fallback := f.routes[req.method+" "+req.path], f.fallback
	f.mu.Unlock()

	var status int
	var body any
	switch {
	case route != nil:
		status, body = route(req)
	case req.method == http.MethodPost && strings.HasSuffix(req.path, "/login"):
		status, body = f.login()
	case req.method == http.MethodPost && req.path == testRevokePath:
		status = http.StatusNoContent
	case fallback != nil:
		status, body = fallback(req)
	default:
		status, body = http.StatusNotFound, withErrors()
	}

	w.WriteHeader(status)
	if body != nil {
		if err := json.NewEncoder(w).Encode(body); err != nil {
			f.t.Errorf("encoding response: %v", err)
		}
	}
}

func (f *fakeBao) login() (int, any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.logins++
	return http.StatusOK, map[string]any{
		"auth": map[string]any{
			"client_token":   fmt.Sprintf("token-%d", f.logins),
			"token_type":     f.tokenType,
			"lease_duration": f.leaseSeconds,
			"metadata":       f.metadata,
		},
	}
}

// sent returns the requests made to method and path, in order.
func (f *fakeBao) sent(method, path string) []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []fakeRequest
	for _, r := range f.requests {
		if r.method == method && r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeBao) all() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeBao) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

func respond(status int, body any) fakeRoute {
	return func(fakeRequest) (int, any) {
		return status, body
	}
}

func withData(data map[string]any) map[string]any {
	return map[string]any{"data": data}
}

func withErrors(msgs ...string) map[string]any {
	if msgs == nil {
		msgs = []string{}
	}
	return map[string]any{"errors": msgs}
}

// keyData is transit's READ keys/<name> data for a key of keyType.
func keyData(keyType string, extra map[string]any) map[string]any {
	data := map[string]any{
		"type":                   keyType,
		"latest_version":         1,
		"min_decryption_version": 1,
		"exportable":             true,
		"soft_deleted":           false,
		"keys":                   map[string]any{"1": 1700000000},
	}
	maps.Copy(data, extra)
	return data
}

func keyRoute(keyType string, extra map[string]any) fakeRoute {
	return respond(http.StatusOK, withData(keyData(keyType, extra)))
}

// newTestSession returns a context carrying a session on bao, as the
// connect hook gives each connection.
func newTestSession(t *testing.T, bao *fakeBao, cfg Config) (context.Context, *session) {
	t.Helper()

	if cfg.AuthMount == "" {
		cfg.AuthMount = "auth/cert"
	}
	tr, err := newTranslator(bao, cfg)
	require.NoError(t, err)

	s := tr.newSession([]*x509.Certificate{testPeer}, testRemoteAddr)
	return context.WithValue(t.Context(), sessionKey{}, s), s
}

// op begins one KMIP operation on the session in ctx.
func op(t *testing.T, ctx context.Context) *call {
	t.Helper()

	c, err := begin(ctx)
	require.NoError(t, err)
	return c
}

func TestSplitAuthMount(t *testing.T) {
	cases := []struct {
		authMount string
		namespace string
		mount     string
	}{
		{"auth/cert", "", "auth/cert"},
		{"/auth/cert/", "", "auth/cert"},
		{"ns1/auth/cert", "ns1", "auth/cert"},
		{"ns1/ns2/auth/kmip/certs", "ns1/ns2", "auth/kmip/certs"},
	}
	for _, tc := range cases {
		namespace, mount, err := splitAuthMount(tc.authMount)
		require.NoError(t, err, tc.authMount)
		require.Equal(t, tc.namespace, namespace, tc.authMount)
		require.Equal(t, tc.mount, mount, tc.authMount)
	}

	for _, authMount := range []string{"", "cert", "ns1/auth", "auth"} {
		_, _, err := splitAuthMount(authMount)
		require.ErrorContains(t, err, "must name a mount under auth/", authMount)
	}
}

func TestTranslator_RequestsCarryClientIdentity(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodPost, "transit/keys/app-a", keyRoute("aes256-gcm96", nil))
	ctx, _ := newTestSession(t, bao, Config{})

	id, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	require.Equal(t, "app-a", id)

	logins := bao.sent(http.MethodPost, testLoginPath)
	require.Len(t, logins, 1)
	require.Empty(t, logins[0].token)
	require.Empty(t, logins[0].body)

	creates := bao.sent(http.MethodPost, "transit/keys/app-a")
	require.Len(t, creates, 1)
	require.Equal(t, "token-1", creates[0].token)
	require.Equal(t, map[string]any{"type": "aes256-gcm96", "exportable": true}, creates[0].body)

	for _, r := range bao.all() {
		require.Empty(t, r.namespace, "%s %s", r.method, r.path)
		require.Equal(t, testRemoteAddr, r.remoteAddr, "%s %s", r.method, r.path)
		require.Equal(t, []*x509.Certificate{testPeer}, r.peerCerts, "%s %s", r.method, r.path)
	}
}

func TestTranslator_AuthMountNamespace(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", respond(http.StatusForbidden, withErrors("permission denied")))
	ctx, _ := newTestSession(t, bao, Config{AuthMount: "/tenant-a/team/auth/kmip-cert/"})

	_, err := op(t, ctx).readKey(ctx, "k")
	require.ErrorContains(t, err, `permission denied: GET tenant-a/team/transit/keys/k requires the "read" capability`)

	require.Len(t, bao.sent(http.MethodPost, "auth/kmip-cert/login"), 2)
	for _, r := range bao.all() {
		require.Equal(t, "tenant-a/team", r.namespace, "%s %s", r.method, r.path)
	}
}

func TestTranslator_TransitMount(t *testing.T) {
	t.Run("cert role overrides listener default", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.route(http.MethodGet, "transit/keys/k", keyRoute("aes256-gcm96", nil))
		ctx, _ := newTestSession(t, bao, Config{DefaultTransitMount: "kmip-default"})

		_, err := op(t, ctx).readKey(ctx, "k")
		require.NoError(t, err)
	})

	t.Run("listener default", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.metadata = map[string]string{"cert_name": "app"}
		bao.route(http.MethodGet, "kmip-default/keys/k", keyRoute("aes256-gcm96", nil))
		ctx, _ := newTestSession(t, bao, Config{DefaultTransitMount: "/kmip-default/"})

		_, err := op(t, ctx).readKey(ctx, "k")
		require.NoError(t, err)
	})

	t.Run("none", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.metadata = map[string]string{"cert_name": "app"}
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).readKey(ctx, "k")
		require.ErrorContains(t, err, `no transit mount for this client: set kmip_transit_mount on cert role "app"`)
		require.Len(t, bao.all(), 1)
	})
}

func TestTranslator_LoginFailure(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodPost, testLoginPath, respond(http.StatusBadRequest,
		withErrors("no chain matching all constraints could be found for this login certificate")))
	ctx, _ := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).readKey(ctx, "k")
	require.ErrorContains(t, err, "login through auth/cert/login failed")
	require.Len(t, bao.all(), 1)
}

func TestTranslator_RetriesOnceAfterForbidden(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", respond(http.StatusForbidden, withErrors("permission denied")))
	ctx, _ := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).readKey(ctx, "k")
	require.ErrorContains(t, err, `permission denied: GET transit/keys/k requires the "read" capability`)

	reads := bao.sent(http.MethodGet, "transit/keys/k")
	require.Len(t, reads, 2)
	require.Equal(t, "token-1", reads[0].token)
	require.Equal(t, "token-2", reads[1].token)
	require.Equal(t, 2, bao.loginCount())

	// The denied token was still live, so logging in again revoked it.
	revokes := bao.sent(http.MethodPost, testRevokePath)
	require.Len(t, revokes, 1)
	require.Equal(t, "token-1", revokes[0].token)
}

func TestTranslator_RetryUsesNewToken(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", func(r fakeRequest) (int, any) {
		if r.token == "token-1" {
			return http.StatusForbidden, withErrors("permission denied")
		}
		return http.StatusOK, withData(keyData("aes256-gcm96", nil))
	})
	ctx, _ := newTestSession(t, bao, Config{})

	info, err := op(t, ctx).readKey(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, "aes256-gcm96", info.Type)
	require.Equal(t, 2, bao.loginCount())
}

func TestTranslator_NoRetryAfterServerError(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", respond(http.StatusInternalServerError, withErrors("storage unavailable")))
	ctx, _ := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).readKey(ctx, "k")
	require.ErrorContains(t, err, "GET transit/keys/k: status 500")
	require.Len(t, bao.sent(http.MethodGet, "transit/keys/k"), 1)
	require.Equal(t, 1, bao.loginCount())
}

func TestTranslator_RejectsNamesOutsideTransitCharset(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	for _, name := range []string{"../sys/seal", "a/b", "key?x", "-lead", "trail-"} {
		_, err := op(t, ctx).create(ctx, name, kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.ErrorContains(t, err, "invalid key name", name)

		_, err = op(t, ctx).get(ctx, name)
		require.ErrorContains(t, err, "invalid key name", name)

		require.ErrorContains(t, op(t, ctx).destroy(ctx, name), "invalid key name", name)
	}
	require.Empty(t, bao.all())
}

func TestTranslator_Create(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.route(http.MethodPost, "transit/keys/app-a", respond(http.StatusOK, map[string]any{
			"data":     keyData("aes256-gcm96", nil),
			"warnings": []string{"key app-a already existed"},
		}))
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.ErrorContains(t, err, `key "app-a" already exists`)
	})

	t.Run("nameless", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.fallback = keyRoute("hmac", map[string]any{"key_size": 64})
		ctx, _ := newTestSession(t, bao, Config{})

		id, err := op(t, ctx).create(ctx, "", kmiplib.CryptographicAlgorithmHMACSHA256, 512, nil)
		require.NoError(t, err)
		require.Regexp(t, `^app-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, id)

		creates := bao.sent(http.MethodPost, "transit/keys/"+id)
		require.Len(t, creates, 1)
		require.Equal(t, map[string]any{"type": "hmac", "key_size": float64(64), "exportable": true}, creates[0].body)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		bao := newFakeBao(t)
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 192, nil)
		require.ErrorContains(t, err, "unsupported algorithm")
		require.Empty(t, bao.all())
	})
}

func TestTranslator_RegisterWrapsMaterial(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/wrapping_key", respond(http.StatusOK, withData(map[string]any{
		"public_key": string(publicPEM),
	})))
	bao.route(http.MethodPost, "transit/keys/app-imported/import", respond(http.StatusNoContent, nil))
	ctx, _ := newTestSession(t, bao, Config{})

	material := []byte("0123456789abcdef0123456789abcdef")
	id, err := op(t, ctx).register(ctx, "app-imported", kmiplib.CryptographicAlgorithmAES, 256, material, nil)
	require.NoError(t, err)
	require.Equal(t, "app-imported", id)

	imports := bao.sent(http.MethodPost, "transit/keys/app-imported/import")
	require.Len(t, imports, 1)
	body := imports[0].body
	require.Equal(t, "aes256-gcm96", body["type"])
	require.Equal(t, "SHA256", body["hash_function"])
	require.Equal(t, true, body["exportable"])
	require.Equal(t, true, body["allow_rotation"])

	encoded, ok := body["ciphertext"].(string)
	require.True(t, ok, "ciphertext is %T", body["ciphertext"])
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Unwrap the way transit's import endpoint does: the RSA-OAEP wrapped
	// AES key, then the KWP wrapped material.
	split := wrappingKey.Size()
	require.Greater(t, len(ciphertext), split)
	ephemeral, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey, ciphertext[:split], []byte{})
	require.NoError(t, err)
	kwp, err := subtle.NewKWP(ephemeral)
	require.NoError(t, err)
	unwrapped, err := kwp.Unwrap(ciphertext[split:])
	require.NoError(t, err)
	require.Equal(t, material, unwrapped)
}

func TestTranslator_Get(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")

	cases := []struct {
		name       string
		keyType    string
		extra      map[string]any
		exportPath string
		format     string
		objType    kmiplib.ObjectType
		alg        kmiplib.CryptographicAlgorithm
		bitlen     int32
	}{
		{"aes", "aes256-gcm96", nil, "transit/export/encryption-key/k/3", "raw", kmiplib.ObjectTypeSymmetricKey, kmiplib.CryptographicAlgorithmAES, 256},
		{"hmac", "hmac", map[string]any{"key_size": 32}, "transit/export/hmac-key/k/3", "raw", kmiplib.ObjectTypeSymmetricKey, kmiplib.CryptographicAlgorithmHMACSHA256, 256},
		{"rsa", "rsa-2048", nil, "transit/export/signing-key/k/3", "der", kmiplib.ObjectTypePrivateKey, kmiplib.CryptographicAlgorithmRSA, 2048},
		{"ecdsa", "ecdsa-p384", nil, "transit/export/signing-key/k/3", "der", kmiplib.ObjectTypePrivateKey, kmiplib.CryptographicAlgorithmECDSA, 384},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{"latest_version": 3}
			maps.Copy(extra, tc.extra)

			bao := newFakeBao(t)
			bao.route(http.MethodGet, "transit/keys/k", keyRoute(tc.keyType, extra))
			bao.route(http.MethodGet, tc.exportPath, respond(http.StatusOK, withData(map[string]any{
				"keys": map[string]string{"3": base64.StdEncoding.EncodeToString(material)},
			})))
			ctx, _ := newTestSession(t, bao, Config{})

			obj, err := op(t, ctx).get(ctx, "k")
			require.NoError(t, err)
			require.Equal(t, tc.objType, obj.ObjectType())

			exports := bao.sent(http.MethodGet, tc.exportPath)
			require.Len(t, exports, 1)
			require.Equal(t, url.Values{"format": {tc.format}}, exports[0].query)

			var block *kmiplib.KeyBlock
			switch o := obj.(type) {
			case *kmiplib.SymmetricKey:
				block = &o.KeyBlock
			case *kmiplib.PrivateKey:
				block = &o.KeyBlock
			default:
				t.Fatalf("unexpected object %T", obj)
			}
			got, err := block.GetBytes()
			require.NoError(t, err)
			require.Equal(t, material, got)
			require.Equal(t, tc.alg, block.CryptographicAlgorithm)
			require.Equal(t, tc.bitlen, block.CryptographicLength)
		})
	}
}

func TestTranslator_GetRefusals(t *testing.T) {
	cases := []struct {
		name  string
		route fakeRoute
		err   string
	}{
		{"soft-deleted", keyRoute("aes256-gcm96", map[string]any{"soft_deleted": true}), "wrong key lifecycle state"},
		{"not exportable", keyRoute("aes256-gcm96", map[string]any{"exportable": false}), `key material of "k" is not exportable`},
		{"missing", respond(http.StatusNotFound, withErrors()), `object "k" not found`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bao := newFakeBao(t)
			bao.route(http.MethodGet, "transit/keys/k", tc.route)
			ctx, _ := newTestSession(t, bao, Config{})

			_, err := op(t, ctx).get(ctx, "k")
			require.ErrorContains(t, err, tc.err)
			require.Empty(t, bao.sent(http.MethodGet, "transit/export/encryption-key/k/1"))
		})
	}
}

func TestTranslator_GetPublicKeyOfNonExportableKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", keyRoute("rsa-2048", map[string]any{
		"exportable": false,
		"keys":       map[string]any{"1": map[string]any{"public_key": pemKey}},
	}))
	ctx, _ := newTestSession(t, bao, Config{})

	obj, err := op(t, ctx).get(ctx, "k")
	require.NoError(t, err)
	pub, ok := obj.(*kmiplib.PublicKey)
	require.True(t, ok, "got %T", obj)
	require.Equal(t, kmiplib.KeyFormatTypeX_509, pub.KeyBlock.KeyFormatType)
	require.Equal(t, kmiplib.CryptographicAlgorithmRSA, pub.KeyBlock.CryptographicAlgorithm)
	require.Equal(t, der, *pub.KeyBlock.KeyValue.Plain.KeyMaterial.Bytes)
	require.Empty(t, bao.sent(http.MethodGet, "transit/export/signing-key/k/1"))
}

func TestTranslator_LocateByExactName(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/app-a", keyRoute("aes256-gcm96", nil))
	bao.route(http.MethodGet, "transit/keys/app-a/metadata", respond(http.StatusOK, withData(map[string]any{"custom_metadata": map[string]string{}, "version": 0})))
	ctx, _ := newTestSession(t, bao, Config{})

	byName := kmiplib.Attribute{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-a", NameType: kmiplib.NameTypeUninterpretedTextString},
	}
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{byName})
	require.NoError(t, err)
	require.Equal(t, []string{"app-a"}, ids)

	// The name is read, never listed, so a policy without list still works.
	require.Len(t, bao.sent(http.MethodGet, "transit/keys/app-a"), 1)
	require.Empty(t, bao.sent("LIST", "transit/keys"))

	ids, err = op(t, ctx).locate(ctx, []kmiplib.Attribute{byName, {
		AttributeName:  kmiplib.AttributeNameObjectType,
		AttributeValue: kmiplib.ObjectTypePrivateKey,
	}})
	require.NoError(t, err)
	require.Empty(t, ids)

	ids, err = op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameUniqueIdentifier,
		AttributeValue: "../sys/seal",
	}})
	require.NoError(t, err)
	require.Empty(t, ids)
	require.Empty(t, bao.sent("LIST", "transit/keys"))
}

// newLocateBao serves a mount whose list holds keys the client may read,
// one it may not, one deleted since the list, and keys of three types.
func newLocateBao(t *testing.T) *fakeBao {
	bao := newFakeBao(t)
	bao.route("LIST", "transit/keys", respond(http.StatusOK, withData(map[string]any{
		"keys": []string{"a", "denied", "gone", "rsa", "e"},
	})))
	bao.route(http.MethodGet, "transit/keys/a", keyRoute("aes256-gcm96", nil))
	bao.route(http.MethodGet, "transit/keys/denied", respond(http.StatusForbidden, withErrors("permission denied")))
	bao.route(http.MethodGet, "transit/keys/gone", respond(http.StatusNotFound, withErrors()))
	bao.route(http.MethodGet, "transit/keys/rsa", keyRoute("rsa-2048", nil))
	bao.route(http.MethodGet, "transit/keys/e", keyRoute("aes128-gcm96", nil))
	return bao
}

func TestTranslator_LocateFiltersCandidates(t *testing.T) {
	bao := newLocateBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameObjectType,
		AttributeValue: kmiplib.ObjectTypeSymmetricKey,
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "e"}, ids)

	// A candidate the client may not read is skipped, not retried.
	require.Len(t, bao.sent(http.MethodGet, "transit/keys/denied"), 1)
	require.Equal(t, 1, bao.loginCount())

	ids, err = op(t, ctx).locate(ctx, []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: kmiplib.CryptographicAlgorithmAES},
		{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(128)},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"e"}, ids)
}

func TestTranslator_LocatePropagatesCandidateErrors(t *testing.T) {
	bao := newLocateBao(t)
	bao.route(http.MethodGet, "transit/keys/rsa", respond(http.StatusInternalServerError, withErrors("storage unavailable")))
	ctx, _ := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).locate(ctx, nil)
	require.ErrorContains(t, err, "GET transit/keys/rsa: status 500")
}

func TestTranslator_LocateEmptyMount(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	// transit lists a mount without keys as a 404
	ids, err := op(t, ctx).locate(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, ids)
	require.Len(t, bao.sent("LIST", "transit/keys"), 1)
}

func TestHandleLocate_Pages(t *testing.T) {
	bao := newLocateBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	resp, err := handleLocate(ctx, &payloads.LocateRequestPayload{OffsetItems: 1, MaximumItems: 1})
	require.NoError(t, err)
	require.Equal(t, []string{"rsa"}, resp.UniqueIdentifier)
	require.NotNil(t, resp.LocatedItems)
	require.Equal(t, int32(3), *resp.LocatedItems)

	resp, err = handleLocate(ctx, &payloads.LocateRequestPayload{OffsetItems: 5})
	require.NoError(t, err)
	require.Empty(t, resp.UniqueIdentifier)
	require.Equal(t, int32(3), *resp.LocatedItems)
}

func TestTranslator_Lifecycle(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("active")

	// Activate of an Active key reads it and writes nothing.
	start := len(bao.all())
	require.NoError(t, op(t, ctx).activate(ctx, "active"))
	require.Equal(t, []string{"GET transit/keys/active", "GET transit/keys/active/metadata"}, since(bao, start))

	// Revoke writes the record, then soft-deletes the key.
	start = len(bao.all())
	require.NoError(t, op(t, ctx).revoke(ctx, "active", unspecified, nil))
	require.Equal(t, []string{
		"GET transit/keys/active", "GET transit/keys/active/metadata",
		"GET transit/keys/active/metadata", "POST transit/keys/active/metadata",
		"DELETE transit/keys/active/soft-delete",
	}, since(bao, start))
	require.True(t, m.key("active").SoftDeleted)
	requireReason(t, op(t, ctx).activate(ctx, "active"), kmiplib.ResultReasonPermissionDenied, "wrong key lifecycle state")
	requireReason(t, op(t, ctx).revoke(ctx, "gone", unspecified, nil), kmiplib.ResultReasonItemNotFound, `object "gone" not found`)

	// Destroy of a soft-deleted key writes the record only, and never
	// deletes the key.
	start = len(bao.all())
	require.NoError(t, op(t, ctx).destroy(ctx, "active"))
	require.Equal(t, []string{
		"GET transit/keys/active", "GET transit/keys/active/metadata",
		"GET transit/keys/active/metadata", "POST transit/keys/active/metadata",
	}, since(bao, start))
	require.NotNil(t, m.key("active"))
	requireReason(t, op(t, ctx).destroy(ctx, "gone"), kmiplib.ResultReasonItemNotFound, `object "gone" not found`)
	for _, r := range bao.all() {
		require.NotEqual(t, http.MethodDelete+" transit/keys/active", r.method+" "+r.path)
	}
}

func TestHandleQuery_AnsweredLocally(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	resp, err := handleQuery(ctx, &payloads.QueryRequestPayload{})
	require.NoError(t, err)
	require.ElementsMatch(t, SupportedOperations, resp.Operations)
	require.NotEmpty(t, resp.VendorIdentification)
	require.Empty(t, bao.all())
}

func TestConnect_RequiresClientCertificate(t *testing.T) {
	tr, err := newTranslator(newFakeBao(t), Config{AuthMount: "auth/cert"})
	require.NoError(t, err)

	ln := newHandshakeListener(nil, time.Second)
	ln.t = tr
	_, err = ln.connect(t.Context())
	require.ErrorContains(t, err, "client certificate required")
}

// A TTL under the refresh margin must not make every request log in again,
// nor cost a 403 more than one login.
func TestSession_ShortTTL(t *testing.T) {
	bao := newFakeBao(t)
	bao.leaseSeconds = 4
	bao.route(http.MethodGet, "transit/keys/k", keyRoute("aes256-gcm96", nil))
	bao.route(http.MethodGet, "transit/keys/denied", respond(http.StatusForbidden, withErrors("permission denied")))
	ctx, _ := newTestSession(t, bao, Config{})

	for range 3 {
		_, err := op(t, ctx).readKey(ctx, "k")
		require.NoError(t, err)
	}
	require.Equal(t, 1, bao.loginCount())

	_, err := op(t, ctx).readKey(ctx, "denied")
	require.ErrorContains(t, err, "permission denied")
	require.Equal(t, 2, bao.loginCount())

	revokes := bao.sent(http.MethodPost, testRevokePath)
	require.Len(t, revokes, 1)
	require.Equal(t, "token-1", revokes[0].token)
}

func TestSession_RefreshRevokesReplacedToken(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", keyRoute("aes256-gcm96", nil))
	ctx, s := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).readKey(ctx, "k")
	require.NoError(t, err)

	// The token is due for refresh but has not expired yet.
	s.mu.Lock()
	s.refresh = time.Now().Add(-time.Second)
	s.mu.Unlock()

	_, err = op(t, ctx).readKey(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, 2, bao.loginCount())

	reads := bao.sent(http.MethodGet, "transit/keys/k")
	require.Len(t, reads, 2)
	require.Equal(t, "token-2", reads[1].token)

	revokes := bao.sent(http.MethodPost, testRevokePath)
	require.Len(t, revokes, 1)
	require.Equal(t, "token-1", revokes[0].token)

	s.close(ctx)
	revokes = bao.sent(http.MethodPost, testRevokePath)
	require.Len(t, revokes, 2)
	require.Equal(t, "token-2", revokes[1].token)
}

func TestSession_Close(t *testing.T) {
	cases := []struct {
		name      string
		tokenType string
		login     bool
		expired   bool
		revoked   bool
	}{
		{name: "service token", tokenType: "service", login: true, revoked: true},
		{name: "batch token", tokenType: "batch", login: true},
		{name: "expired token", tokenType: "service", login: true, expired: true},
		{name: "never logged in", tokenType: "service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bao := newFakeBao(t)
			bao.tokenType = tc.tokenType
			bao.route(http.MethodGet, "transit/keys/k", keyRoute("aes256-gcm96", nil))
			ctx, s := newTestSession(t, bao, Config{})

			if tc.login {
				_, err := op(t, ctx).readKey(ctx, "k")
				require.NoError(t, err)
			}
			if tc.expired {
				s.mu.Lock()
				s.expiry = time.Now().Add(-time.Second)
				s.mu.Unlock()
			}

			// The connection's context is already cancelled when it closes.
			closed, cancel := context.WithCancel(ctx)
			cancel()
			s.close(closed)

			revokes := bao.sent(http.MethodPost, testRevokePath)
			if !tc.revoked {
				require.Empty(t, revokes)
				return
			}
			require.Len(t, revokes, 1)
			require.Equal(t, "token-1", revokes[0].token)
			require.NoError(t, revokes[0].ctxErr)
		})
	}
}

// transitMount serves the fakeBao's transit mount from a real transit
// backend, the way the HTTP handler would, so the translator meets
// transit's own answers: its metadata operations and locking, and its
// create of an existing key, which returns that key without a warning.
type transitMount struct {
	t       *testing.T
	backend logical.Backend
	storage *observedStorage

	mu sync.Mutex
	// intercept, when set, sees each request first. It answers the request
	// itself, or calls serve and returns that answer or another.
	intercept func(r fakeRequest, serve func() (int, any)) (int, any)
}

// observedStorage reports each write. Transit writes a key's metadata under
// the key's exclusive lock, so writes to one record arrive in commit order.
type observedStorage struct {
	*logical.InmemStorage

	mu    sync.Mutex
	onPut func(*logical.StorageEntry)
}

func (s *observedStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if err := s.InmemStorage.Put(ctx, entry); err != nil {
		return err
	}
	s.mu.Lock()
	onPut := s.onPut
	s.mu.Unlock()
	if onPut != nil {
		onPut(entry)
	}
	return nil
}

// transitBao returns a fakeBao whose transit mount is a real transit
// backend. Routes set on the fakeBao still come first.
func transitBao(t *testing.T) (*fakeBao, *transitMount) {
	t.Helper()

	config := logical.TestBackendConfig()
	storage := &observedStorage{InmemStorage: &logical.InmemStorage{}}
	config.StorageView = storage
	backend, err := transit.Factory(t.Context(), config)
	require.NoError(t, err)

	m := &transitMount{t: t, backend: backend, storage: storage}
	bao := newFakeBao(t)
	bao.fallback = m.serve
	return bao, m
}

func (m *transitMount) serve(r fakeRequest) (int, any) {
	m.mu.Lock()
	intercept := m.intercept
	m.mu.Unlock()
	if intercept != nil {
		return intercept(r, func() (int, any) { return m.handle(r) })
	}
	return m.handle(r)
}

func (m *transitMount) handle(r fakeRequest) (int, any) {
	path, ok := strings.CutPrefix(r.path, "transit/")
	if !ok {
		return http.StatusNotFound, withErrors()
	}
	operation := map[string]logical.Operation{
		http.MethodGet:    logical.ReadOperation,
		http.MethodPost:   logical.UpdateOperation,
		http.MethodPatch:  logical.PatchOperation,
		http.MethodDelete: logical.DeleteOperation,
		"LIST":            logical.ListOperation,
	}[r.method]

	req := &logical.Request{Operation: operation, Path: path, Data: r.body, Storage: m.storage}
	resp, err := m.backend.HandleRequest(context.Background(), req)
	if status, err := logical.RespondErrorCommon(req, resp, err); status != 0 {
		if err != nil {
			return status, withErrors(err.Error())
		}
		return status, withErrors()
	}
	if resp == nil {
		return http.StatusNoContent, nil
	}
	return http.StatusOK, map[string]any{"data": resp.Data, "warnings": resp.Warnings}
}

// do sends a request to the mount directly, not through KMIP.
func (m *transitMount) do(method, path string, body map[string]any) (int, []byte) {
	m.t.Helper()
	status, out := m.handle(fakeRequest{method: method, path: "transit/" + path, body: body})
	raw, err := json.Marshal(out)
	require.NoError(m.t, err)
	return status, raw
}

func (m *transitMount) createKey(name string) {
	m.t.Helper()
	status, raw := m.do(http.MethodPost, "keys/"+name, map[string]any{"type": "aes256-gcm96", "exportable": true})
	require.Equal(m.t, http.StatusOK, status, string(raw))
}

func (m *transitMount) write(name string, ops ...metadataOp) {
	m.t.Helper()
	status, raw := m.do(http.MethodGet, "keys/"+name+"/metadata", nil)
	require.Equal(m.t, http.StatusOK, status, string(raw))
	var out struct {
		Data struct {
			Data    map[string]string `json:"custom_metadata"`
			Version uint64            `json:"version"`
		} `json:"data"`
	}
	require.NoError(m.t, json.Unmarshal(raw, &out))
	record, err := decodeMetadata(out.Data.Data)
	require.NoError(m.t, err)
	for _, op := range ops {
		require.NoError(m.t, record.apply(op))
	}
	data := out.Data.Data
	for key := range data {
		if strings.HasPrefix(key, "kmip/") {
			delete(data, key)
		}
	}
	for entry, values := range record[metadataScope] {
		encoded, err := json.Marshal(values)
		require.NoError(m.t, err)
		data[metadataScope+"/"+entry] = string(encoded)
	}
	status, raw = m.do(http.MethodPost, "keys/"+name+"/metadata", map[string]any{"custom_metadata": data, "cas": out.Data.Version})
	require.Equal(m.t, http.StatusOK, status, string(raw))
}

// key reads a key as KMIP does, or returns nil when it is missing.
func (m *transitMount) key(name string) *keyInfo {
	m.t.Helper()
	status, raw := m.do(http.MethodGet, "keys/"+name, nil)
	if status == http.StatusNotFound {
		return nil
	}
	require.Equal(m.t, http.StatusOK, status, string(raw))
	var out struct {
		Data keyInfo `json:"data"`
	}
	require.NoError(m.t, json.Unmarshal(raw, &out))
	status, raw = m.do(http.MethodGet, "keys/"+name+"/metadata", nil)
	require.Equal(m.t, http.StatusOK, status, string(raw))
	var stored struct {
		Data struct {
			Data map[string]string `json:"custom_metadata"`
		} `json:"data"`
	}
	require.NoError(m.t, json.Unmarshal(raw, &stored))
	metadata, err := decodeMetadata(stored.Data.Data)
	require.NoError(m.t, err)
	out.Data.Metadata = metadata
	return &out.Data
}

// record returns the kmip scope of a key's metadata record.
func (m *transitMount) record(name string) map[string][]string {
	m.t.Helper()
	info := m.key(name)
	require.NotNil(m.t, info, "key %s", name)
	return info.Metadata[metadataScope]
}

func (m *transitMount) keys() []string {
	m.t.Helper()
	status, raw := m.do("LIST", "keys", nil)
	require.Equal(m.t, http.StatusOK, status, string(raw))
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	require.NoError(m.t, json.Unmarshal(raw, &out))
	return out.Data.Keys
}

// failOnce fails the first request that matches with a 500. With applied,
// the mount serves the request first, so it takes effect and only its
// answer is lost.
func (m *transitMount) failOnce(match func(fakeRequest) bool, applied bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var once sync.Once
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		fail := false
		if match(r) {
			once.Do(func() { fail = true })
		}
		if !fail {
			return serve()
		}
		if applied {
			serve()
		}
		return http.StatusInternalServerError, withErrors("injected failure")
	}
}

// pauseAt holds the first request with token that matches until release
// is closed. It closes reached when that request arrives.
func (m *transitMount) pauseAt(token string, match func(fakeRequest) bool) (reached, release chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	reached, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		pause := false
		if r.token == token && match(r) {
			once.Do(func() { pause = true })
		}
		if pause {
			close(reached)
			<-release
		}
		return serve()
	}
	return reached, release
}

// metadataWriteRecord decodes the whole custom map sent by the adapter.
func metadataWriteRecord(r fakeRequest) metadataRecord {
	raw, err := json.Marshal(r.body["custom_metadata"])
	if err != nil {
		return nil
	}
	var data map[string]string
	if json.Unmarshal(raw, &data) != nil || data == nil {
		return nil
	}
	record, err := decodeMetadata(data)
	if err != nil {
		return nil
	}
	return record
}

// Match the state a ReKey step writes, rather than an operation envelope.
func isMetadataWrite(r fakeRequest, key, op, entry string) bool {
	if r.method != http.MethodPost || r.path != "transit/keys/"+key+"/metadata" {
		return false
	}
	record := metadataWriteRecord(r)
	if record == nil {
		return false
	}
	values := record[metadataScope][entry]
	switch op {
	case "delete":
		return len(values) == 0 && len(record[metadataScope][entryCurrent]) == 0 && len(record[metadataScope][linkEntry(kmiplib.LinkTypeReplacementObjectLink)]) == 0
	case "claim":
		return len(values) == 1 && values[0] == key+".2" && len(record[metadataScope][linkEntry(kmiplib.LinkTypeReplacementObjectLink)]) == 0
	case "link":
		return len(values) == 1 && values[0] == key+".2"
	}
	return false
}

// since returns the requests after the first n, as "METHOD path", and
// leaves out logins.
func since(bao *fakeBao, n int) []string {
	var out []string
	for _, r := range bao.all()[n:] {
		if strings.HasSuffix(r.path, "/login") {
			continue
		}
		out = append(out, r.method+" "+r.path)
	}
	return out
}

func customAttr(name, value string) kmiplib.Attribute {
	return kmiplib.Attribute{AttributeName: kmiplib.AttributeName(name), AttributeValue: value}
}

func attrsNamed(attrs []kmiplib.Attribute, name kmiplib.AttributeName) []kmiplib.Attribute {
	var out []kmiplib.Attribute
	for _, attr := range attrs {
		if attr.AttributeName == name {
			out = append(out, attr)
		}
	}
	return out
}

// requireAttr checks that attrs hold exactly one instance named name, equal
// to value.
func requireAttr(t *testing.T, attrs []kmiplib.Attribute, name kmiplib.AttributeName, value any) {
	t.Helper()
	got := attrsNamed(attrs, name)
	require.Len(t, got, 1, "instances of %s", name)
	require.True(t, sameValue(kmiplib.Attribute{AttributeName: name, AttributeValue: value}, got[0]),
		"%s is %v, want %v", name, got[0].AttributeValue, value)
}

var (
	testActivation = time.Unix(1700000000, 0)
	// A stored Deactivation Date at or before now makes State Deactivated,
	// so the one every Active test key carries lies far ahead.
	testDeactivation = time.Unix(4000000000, 0)

	// unspecified is the Revocation Reason of a Revoke that deactivates.
	unspecified = kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeUnspecified}
)

// newRekeyKey creates the AES key app-r through KMIP with one instance of
// each kind of stored attribute.
func newRekeyKey(t *testing.T, ctx context.Context) {
	t.Helper()

	_, err := op(t, ctx).create(ctx, "app-r", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	for _, attr := range []kmiplib.Attribute{
		customAttr("x-tag", "blue"),
		{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt},
		{AttributeName: kmiplib.AttributeNameActivationDate, AttributeValue: testActivation},
		{AttributeName: kmiplib.AttributeNameDeactivationDate, AttributeValue: testDeactivation},
	} {
		require.NoError(t, op(t, ctx).addAttribute(ctx, "app-r", attr))
	}
}

// requireRekeyed checks that ReKey replaced pred with succ, generation gen
// of the Name anchor, exactly once: one instance of every entry, both
// links, no marker left behind.
func requireRekeyed(t *testing.T, m *transitMount, anchor, pred, succ string, gen int) {
	t.Helper()

	p, s := m.record(pred), m.record(succ)
	require.Equal(t, []string{succ}, p[linkEntry(kmiplib.LinkTypeReplacementObjectLink)])
	require.NotContains(t, p, entryPending)
	require.Equal(t, []string{pred}, s[linkEntry(kmiplib.LinkTypeReplacedObjectLink)])
	require.Equal(t, []string{anchor}, s[entryAnchor])
	require.Equal(t, []string{strconv.Itoa(gen)}, s[entryGeneration])
	for entry, values := range p {
		if strings.HasPrefix(entry, entryAttrPrefix) {
			require.Equal(t, values, s[entry], "entry %s", entry)
		}
	}
	for entry, values := range s {
		require.Len(t, values, 1, "entry %s", entry)
	}
}

func TestTranslator_AddAttribute(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)

	start := len(bao.all())
	tag := customAttr("x-tag", "blue")
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", tag))
	writes := bao.sent(http.MethodPost, "transit/keys/app-a/metadata")
	require.Len(t, writes, 1)
	encoded, err := json.Marshal([]string{encodeAttr(tag)})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"custom_metadata": map[string]any{"kmip/attr/x-tag": string(encoded)}, "cas": float64(0)}, writes[0].body)
	require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata", "GET transit/keys/app-a/metadata", "POST transit/keys/app-a/metadata"}, since(bao, start))

	// GetAttributes reads both the key and its metadata.
	start = len(bao.all())
	attrs, err := op(t, ctx).getAttributes(ctx, "app-a", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))
	requireAttr(t, attrs, "x-tag", "blue")
	requireAttr(t, attrs, kmiplib.AttributeNameName, kmiplib.Name{NameValue: "app-a", NameType: kmiplib.NameTypeUninterpretedTextString})
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateActive)
	requireAttr(t, attrs, kmiplib.AttributeNameCryptographicLength, int32(256))

	names, err := op(t, ctx).getAttributeList(ctx, "app-a")
	require.NoError(t, err)
	require.Equal(t, []kmiplib.AttributeName{
		kmiplib.AttributeNameName,
		kmiplib.AttributeNameUniqueIdentifier,
		kmiplib.AttributeNameObjectType,
		kmiplib.AttributeNameCryptographicAlgorithm,
		kmiplib.AttributeNameCryptographicLength,
		kmiplib.AttributeNameState,
		kmiplib.AttributeNameInitialDate,
		kmiplib.AttributeNameActivationDate,
		"x-tag",
	}, names)

	// A multi-instance attribute keeps every instance, and the filter
	// returns every instance with its index.
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", customAttr("x-tag", "green")))
	attrs, err = op(t, ctx).getAttributes(ctx, "app-a", []kmiplib.AttributeName{"x-tag"})
	require.NoError(t, err)
	require.Len(t, attrs, 2)
	require.Nil(t, attrs[0].AttributeIndex)
	require.Equal(t, int32(1), *attrs[1].AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "green"), attrs[1]))
}

func TestTranslator_AddAttributeRefusals(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	start := len(bao.all())

	// A derived attribute is refused before any request.
	err = op(t, ctx).addAttribute(ctx, "app-a", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameState, AttributeValue: kmiplib.StateActive})
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "attribute State is set by the server")
	require.Empty(t, since(bao, start))

	// The object's own Name is a no-op; another Name is a rename.
	sameName := kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-a"}}
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", sameName))
	otherName := kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-b"}}
	err = op(t, ctx).addAttribute(ctx, "app-a", otherName)
	requireReason(t, err, kmiplib.ResultReasonInvalidField, `renaming is not supported: object "app-a" has the Name "app-a"`)

	// A malformed value is an invalid field.
	err = op(t, ctx).addAttribute(ctx, "app-a", kmiplib.Attribute{AttributeName: "x-empty"})
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "attribute x-empty has no value")
	err = op(t, ctx).addAttribute(ctx, "app-a", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: "app-a"})
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "Name attribute is empty or invalid")

	require.Empty(t, bao.sent(http.MethodPost, "transit/keys/app-a/metadata"))

	// A single-instance attribute takes one value.
	mask := func(m kmiplib.CryptographicUsageMask) kmiplib.Attribute {
		return kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: m}
	}
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", mask(kmiplib.CryptographicUsageEncrypt)))
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", mask(kmiplib.CryptographicUsageEncrypt)))
	err = op(t, ctx).addAttribute(ctx, "app-a", mask(kmiplib.CryptographicUsageDecrypt))
	requireReason(t, err, kmiplib.ResultReasonInvalidField, `object "app-a" already has a Cryptographic Usage Mask`)

	// A record over transit's bounds is an invalid field.
	err = op(t, ctx).addAttribute(ctx, "app-a", customAttr("x-big", strings.Repeat("v", 8<<10)))
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "invalid request")

	// A missing object is not found.
	err = op(t, ctx).addAttribute(ctx, "app-missing", customAttr("x-tag", "blue"))
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, `object "app-missing" not found`)
}

func requireReason(t *testing.T, err error, reason kmiplib.ResultReason, msg string) {
	t.Helper()
	require.ErrorContains(t, err, msg)
	kerr, ok := errors.AsType[kmipserver.Error](err)
	require.True(t, ok, "%T: %v", err, err)
	require.Equal(t, reason, kerr.Reason)
}

func TestTranslator_MetadataWriteDenied(t *testing.T) {
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/k", keyRoute("aes256-gcm96", nil))
	bao.route(http.MethodGet, "transit/keys/k/metadata", respond(http.StatusOK, withData(map[string]any{"custom_metadata": map[string]string{}, "version": 0})))
	bao.route(http.MethodPost, "transit/keys/k/metadata", respond(http.StatusForbidden, withErrors("permission denied")))
	ctx, _ := newTestSession(t, bao, Config{})

	err := op(t, ctx).addAttribute(ctx, "k", customAttr("x-tag", "blue"))
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied,
		`permission denied: POST transit/keys/k/metadata requires the "update" capability`)
}

// The mask is stored and reported, not enforced: transit has no use mask,
// and gating the crypto operations on it would cost them a read.
func TestTranslator_UsageMaskIsNotEnforced(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)

	verifyOnly := kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageVerify}
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", verifyOnly))
	attrs, err := op(t, ctx).getAttributes(ctx, "app-a", []kmiplib.AttributeName{kmiplib.AttributeNameCryptographicUsageMask})
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameCryptographicUsageMask, kmiplib.CryptographicUsageVerify)

	_, err = op(t, ctx).encrypt(ctx, "app-a", []byte("still allowed"))
	require.NoError(t, err)

	// A revoked key is refused by transit itself.
	require.NoError(t, op(t, ctx).revoke(ctx, "app-a", unspecified, nil))
	_, err = op(t, ctx).encrypt(ctx, "app-a", []byte("refused"))
	require.ErrorContains(t, err, "invalid request")
}

// The crypto operations send one request each, as before attributes
// existed: no key read and no metadata read.
func TestTranslator_CryptoRequestsUnchanged(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("app-aes")
	status, raw := m.do(http.MethodPost, "keys/app-rsa", map[string]any{"type": "rsa-2048"})
	require.Equal(t, http.StatusOK, status, string(raw))

	start := len(bao.all())
	ciphertext, err := op(t, ctx).encrypt(ctx, "app-aes", []byte("data"))
	require.NoError(t, err)
	require.Equal(t, []string{"POST transit/encrypt/app-aes"}, since(bao, start))

	start = len(bao.all())
	_, err = op(t, ctx).decrypt(ctx, "app-aes", ciphertext)
	require.NoError(t, err)
	require.Equal(t, []string{"POST transit/decrypt/app-aes"}, since(bao, start))

	start = len(bao.all())
	signature, err := op(t, ctx).sign(ctx, "app-rsa", []byte("data"))
	require.NoError(t, err)
	require.Equal(t, []string{"POST transit/sign/app-rsa"}, since(bao, start))

	start = len(bao.all())
	valid, err := op(t, ctx).verify(ctx, "app-rsa", []byte("data"), signature)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, []string{"POST transit/verify/app-rsa"}, since(bao, start))
}

func TestTranslator_ReservedNameSuffix(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	_, err := op(t, ctx).create(ctx, "app-a.2", kmiplib.CryptographicAlgorithmAES, 256, nil)
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "reserved for the replacements ReKey creates")
	_, err = op(t, ctx).register(ctx, "app-a.10", kmiplib.CryptographicAlgorithmAES, 256, make([]byte, 32), nil)
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "reserved for the replacements ReKey creates")
	require.Empty(t, bao.all())
}

func TestTranslator_Rekey(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	start := len(bao.all())
	id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.2", id)

	// The marker is written before the successor is created, and cleared
	// after its record is written; the Name moves before the link.
	require.Equal(t, []string{
		"GET transit/keys/app-r",
		"GET transit/keys/app-r/metadata",
		"GET transit/keys/app-r.2",
		"GET transit/keys/app-r/metadata",
		"POST transit/keys/app-r/metadata",
		"POST transit/keys/app-r.2",
		"GET transit/keys/app-r.2/metadata",
		"POST transit/keys/app-r.2/metadata",
		"GET transit/keys/app-r/metadata",
		"POST transit/keys/app-r/metadata",
		"GET transit/keys/app-r/metadata",
		"POST transit/keys/app-r/metadata",
		"GET transit/keys/app-r/metadata",
		"POST transit/keys/app-r/metadata",
	}, since(bao, start))
	writes := bao.sent(http.MethodPost, "transit/keys/app-r/metadata")
	writes = writes[len(writes)-4:]
	for i, want := range [][2]string{
		{"claim", entryPending},
		{"delete", entryPending},
		{"claim", entryCurrent},
		{"link", linkEntry(kmiplib.LinkTypeReplacementObjectLink)},
	} {
		require.True(t, isMetadataWrite(writes[i], "app-r", want[0], want[1]), "%v", writes[i].body)
	}
	requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	require.Equal(t, []string{"app-r", "app-r.2"}, m.keys())

	// The replacement has the Name and the stored attributes.
	attrs, err := op(t, ctx).getAttributes(ctx, "app-r.2", nil)
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameName, kmiplib.Name{NameValue: "app-r", NameType: kmiplib.NameTypeUninterpretedTextString})
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateActive)
	requireAttr(t, attrs, kmiplib.AttributeNameLink, kmiplib.Link{LinkType: kmiplib.LinkTypeReplacedObjectLink, LinkedObjectIdentifier: "app-r"})
	requireAttr(t, attrs, "x-tag", "blue")
	requireAttr(t, attrs, kmiplib.AttributeNameCryptographicUsageMask, kmiplib.CryptographicUsageEncrypt)
	requireAttr(t, attrs, kmiplib.AttributeNameActivationDate, testActivation)
	requireAttr(t, attrs, kmiplib.AttributeNameDeactivationDate, testDeactivation)

	// The predecessor stays readable, Deactivated and without a Name.
	attrs, err = op(t, ctx).getAttributes(ctx, "app-r", nil)
	require.NoError(t, err)
	require.Empty(t, attrsNamed(attrs, kmiplib.AttributeNameName))
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateDeactivated)
	requireAttr(t, attrs, kmiplib.AttributeNameLink, kmiplib.Link{LinkType: kmiplib.LinkTypeReplacementObjectLink, LinkedObjectIdentifier: "app-r.2"})
	require.False(t, m.key("app-r").SoftDeleted)
	_, err = op(t, ctx).get(ctx, "app-r")
	require.NoError(t, err)

	// The pending_successor marker is never an attribute.
	names, err := op(t, ctx).getAttributeList(ctx, "app-r")
	require.NoError(t, err)
	for _, name := range names {
		require.NotContains(t, string(name), "pending")
	}

	// Locate by Name reads the anchor and replacement with their metadata,
	// without a list.
	start = len(bao.all())
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-r", NameType: kmiplib.NameTypeUninterpretedTextString},
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"app-r.2"}, ids)
	require.Equal(t, []string{"GET transit/keys/app-r", "GET transit/keys/app-r/metadata", "GET transit/keys/app-r.2", "GET transit/keys/app-r.2/metadata"}, since(bao, start))

	// The predecessor cannot be rekeyed again, and its Name is gone.
	_, err = op(t, ctx).rekey(ctx, "app-r", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `ReKey replaced it with "app-r.2"`)
	err = op(t, ctx).addAttribute(ctx, "app-r", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-r"}})
	requireReason(t, err, kmiplib.ResultReasonInvalidField, `object "app-r" was replaced by "app-r.2" and has no Name`)
}

func TestTranslator_RekeyTemplateAndRefusals(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	offset := time.Hour
	_, err := op(t, ctx).rekey(ctx, "app-r", &offset, nil)
	requireReason(t, err, kmiplib.ResultReasonFeatureNotSupported, "ReKey with an Offset is not supported")

	longer := &kmiplib.TemplateAttribute{Attribute: []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(128)},
	}}
	_, err = op(t, ctx).rekey(ctx, "app-r", nil, longer)
	requireReason(t, err, kmiplib.ResultReasonFeatureNotSupported, "ReKey cannot change the Cryptographic Length")

	rename := &kmiplib.TemplateAttribute{Attribute: []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-other"}},
	}}
	_, err = op(t, ctx).rekey(ctx, "app-r", nil, rename)
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "renaming is not supported")
	require.Equal(t, []string{"app-r"}, m.keys())

	// A template attribute replaces the copied one.
	template := &kmiplib.TemplateAttribute{Attribute: []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(256)},
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-r"}},
		customAttr("x-tag", "red"),
	}}
	id, err := op(t, ctx).rekey(ctx, "app-r", nil, template)
	require.NoError(t, err)
	attrs, err := op(t, ctx).getAttributes(ctx, id, []kmiplib.AttributeName{"x-tag"})
	require.NoError(t, err)
	requireAttr(t, attrs, "x-tag", "red")

	// Only symmetric keys are rekeyed.
	status, raw := m.do(http.MethodPost, "keys/app-rsa", map[string]any{"type": "rsa-2048"})
	require.Equal(t, http.StatusOK, status, string(raw))
	_, err = op(t, ctx).rekey(ctx, "app-rsa", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonFeatureNotSupported, "ReKey replaces symmetric keys only")

	// A soft-deleted key is refused.
	m.createKey("app-gone")
	require.NoError(t, op(t, ctx).revoke(ctx, "app-gone", unspecified, nil))
	_, err = op(t, ctx).rekey(ctx, "app-gone", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "wrong key lifecycle state")
}

// ReKey sets the ID Placeholder, so a later batch item without a UID acts
// on the replacement.
func TestHandleRekey_SetsIdPlaceholder(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	exec := kmipserver.NewBatchExecutor()
	for op, h := range routes() {
		exec.Route(op, h)
	}
	msg := kmiplib.NewRequestMessage(
		kmiplib.V1_4,
		&payloads.RekeyRequestPayload{UniqueIdentifier: "app-r"},
		&payloads.GetAttributesRequestPayload{AttributeName: []kmiplib.AttributeName{kmiplib.AttributeNameUniqueIdentifier}},
	)
	resp := exec.HandleRequest(ctx, &msg)
	require.Len(t, resp.BatchItem, 2)
	for _, item := range resp.BatchItem {
		require.NoError(t, item.Err())
	}
	require.Equal(t, "app-r.2", resp.BatchItem[0].ResponsePayload.(*payloads.RekeyResponsePayload).UniqueIdentifier)
	require.Equal(t, "app-r.2", resp.BatchItem[1].ResponsePayload.(*payloads.GetAttributesResponsePayload).UniqueIdentifier)
}

// AddAttribute answers with the Attribute Index that GetAttributes gives the
// new instance. KMIP lets a response omit the index only when it is 0, so the
// second and later instances must carry theirs.
func TestHandleAddAttribute_ReturnsIndex(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	// newRekeyKey stores an x-tag, so use a name it leaves unset.
	newRekeyKey(t, ctx)

	exec := kmipserver.NewBatchExecutor()
	for op, h := range routes() {
		exec.Route(op, h)
	}
	add := func(value string) *int32 {
		t.Helper()
		msg := kmiplib.NewRequestMessage(
			kmiplib.V1_4,
			&payloads.AddAttributeRequestPayload{UniqueIdentifier: "app-r", Attribute: customAttr("x-color", value)},
		)
		resp := exec.HandleRequest(ctx, &msg)
		require.Len(t, resp.BatchItem, 1)
		require.NoError(t, resp.BatchItem[0].Err())
		return resp.BatchItem[0].ResponsePayload.(*payloads.AddAttributeResponsePayload).Attribute.AttributeIndex
	}

	require.Nil(t, add("red"), "index 0 is omitted")
	idx := add("green")
	require.NotNil(t, idx)
	require.Equal(t, int32(1), *idx)
	idx = add("blue")
	require.NotNil(t, idx)
	require.Equal(t, int32(2), *idx)

	// GetAttributes numbers the same instances the same way.
	attrs, err := op(t, ctx).getAttributes(ctx, "app-r", nil)
	require.NoError(t, err)
	tags := attrsNamed(attrs, "x-color")
	require.Len(t, tags, 3)
	require.Nil(t, tags[0].AttributeIndex)
	require.Equal(t, int32(1), *tags[1].AttributeIndex)
	require.Equal(t, int32(2), *tags[2].AttributeIndex)
}

func TestTranslator_RekeyRetention(t *testing.T) {
	t.Run("retain 2", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.metadata["kmip_rekey_retain"] = "2"
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)

		id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.False(t, m.key("app-r").SoftDeleted)
		require.False(t, m.key("app-r.2").SoftDeleted)

		id, err = op(t, ctx).rekey(ctx, id, nil, nil)
		require.NoError(t, err)
		require.Equal(t, "app-r.3", id)
		requireRekeyed(t, m, "app-r", "app-r.2", "app-r.3", 3)

		// The anchor's material is gone, its record is not: the Name still
		// resolves.
		require.True(t, m.key("app-r").SoftDeleted)
		require.False(t, m.key("app-r.2").SoftDeleted)
		require.Equal(t, []string{"1"}, m.record("app-r")[entrySwept])
		ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
			AttributeName:  kmiplib.AttributeNameName,
			AttributeValue: kmiplib.Name{NameValue: "app-r"},
		}})
		require.NoError(t, err)
		require.Equal(t, []string{"app-r.3"}, ids)
	})

	t.Run("retain 1", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.metadata["kmip_rekey_retain"] = "1"
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)

		_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.True(t, m.key("app-r").SoftDeleted)
		require.False(t, m.key("app-r.2").SoftDeleted)
	})

	t.Run("sweep denied", func(t *testing.T) {
		var logs bytes.Buffer
		bao, m := transitBao(t)
		bao.metadata["kmip_rekey_retain"] = "1"
		bao.route(http.MethodDelete, "transit/keys/app-r/soft-delete", respond(http.StatusForbidden, withErrors("permission denied")))
		ctx, _ := newTestSession(t, bao, Config{Logger: hclog.New(&hclog.LoggerOptions{Output: &logs})})
		newRekeyKey(t, ctx)

		// The ReKey succeeded at its commit; the sweep only warns.
		id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.Equal(t, "app-r.2", id)
		require.False(t, m.key("app-r").SoftDeleted)
		require.NotContains(t, m.record("app-r"), entrySwept)
		require.Contains(t, logs.String(), "KMIP ReKey left an old generation readable")
		require.Contains(t, logs.String(), "path=transit/keys/app-r/soft-delete capability=delete")
		// A denied sweep does not log in again.
		require.Equal(t, 1, bao.loginCount())

		// Once the policy allows it, the next ReKey of the Name sweeps what
		// the last one left.
		bao.mu.Lock()
		delete(bao.routes, http.MethodDelete+" transit/keys/app-r/soft-delete")
		bao.mu.Unlock()
		_, err = op(t, ctx).rekey(ctx, id, nil, nil)
		require.NoError(t, err)
		require.Len(t, bao.sent(http.MethodDelete, "transit/keys/app-r/soft-delete"), 2)
		require.True(t, m.key("app-r").SoftDeleted)
		require.True(t, m.key("app-r.2").SoftDeleted)
		require.False(t, m.key("app-r.3").SoftDeleted)
		require.Equal(t, []string{"2"}, m.record("app-r")[entrySwept])
	})
}

func TestTranslator_RekeySuccessorExists(t *testing.T) {
	t.Run("foreign key", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)
		m.createKey("app-r.2")

		start := len(bao.all())
		_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `must create the key "app-r.2", which already exists and is not its replacement`)
		// A recordless S with no marker is read again, with P, before it is
		// called foreign: a concurrent ReKey may have made it.
		require.Equal(t, []string{
			"GET transit/keys/app-r", "GET transit/keys/app-r/metadata", "GET transit/keys/app-r.2", "GET transit/keys/app-r.2/metadata",
			"GET transit/keys/app-r", "GET transit/keys/app-r/metadata", "GET transit/keys/app-r.2", "GET transit/keys/app-r.2/metadata",
		}, since(bao, start))
	})

	t.Run("foreign record despite marker", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)
		m.write("app-r", claimOp(entryPending, "app-r.2", ""))
		m.createKey("app-r.2")
		m.write("app-r.2", linkOp(linkEntry(kmiplib.LinkTypeReplacedObjectLink), "app-other"))

		start := len(bao.all())
		_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.ErrorContains(t, err, `"app-r.2", which already exists`)
		require.Equal(t, []string{"GET transit/keys/app-r", "GET transit/keys/app-r/metadata", "GET transit/keys/app-r.2", "GET transit/keys/app-r.2/metadata"}, since(bao, start))
	})

	t.Run("recordless with marker is adopted", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)
		m.write("app-r", claimOp(entryPending, "app-r.2", ""))
		m.createKey("app-r.2")

		id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.Equal(t, "app-r.2", id)
		require.Empty(t, bao.sent(http.MethodPost, "transit/keys/app-r.2"))
		requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	})

	t.Run("marker with missing successor creates it", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)
		m.write("app-r", claimOp(entryPending, "app-r.2", ""))

		// The marker is neither an attribute nor a state.
		attrs, err := op(t, ctx).getAttributes(ctx, "app-r", nil)
		require.NoError(t, err)
		requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateActive)
		for _, attr := range attrs {
			require.NotContains(t, string(attr.AttributeName), "pending")
		}

		id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.Equal(t, "app-r.2", id)
		require.Len(t, bao.sent(http.MethodPost, "transit/keys/app-r.2"), 1)
		requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	})

	t.Run("record links back, so resume", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newRekeyKey(t, ctx)
		// Stop after step 4, the successor's record, and before the
		// marker is cleared.
		m.failOnce(func(r fakeRequest) bool { return isMetadataWrite(r, "app-r", "delete", entryPending) }, false)
		_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.ErrorContains(t, err, "status 500")

		start := len(bao.all())
		id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
		require.NoError(t, err)
		require.Equal(t, "app-r.2", id)
		require.NotContains(t, since(bao, start), "POST transit/keys/app-r.2")
		require.NotContains(t, since(bao, start), "POST transit/keys/app-r.2/metadata")
		requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	})
}

// Transit answers a create of an existing key with that key and no
// warning: backend.go getPolicy reports every policy as upserted. ReKey
// therefore detects an existing successor by reading it, never by the
// warning.
func TestTranslator_TransitCreateOfExistingKeyHasNoWarning(t *testing.T) {
	_, m := transitBao(t)
	m.createKey("dup")
	status, raw := m.do(http.MethodPost, "keys/dup", map[string]any{"type": "aes256-gcm96"})
	require.Equal(t, http.StatusOK, status)
	var out struct {
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Empty(t, out.Warnings)
}

// A ReKey interrupted at any step completes when the client retries it,
// whether the failed request took effect or not.
func TestTranslator_RekeyInterrupted(t *testing.T) {
	boundaries := []struct {
		name  string
		match func(fakeRequest) bool
	}{
		{"marker", func(r fakeRequest) bool { return isMetadataWrite(r, "app-r", "claim", entryPending) }},
		{"create", func(r fakeRequest) bool { return r.method == http.MethodPost && r.path == "transit/keys/app-r.2" }},
		{"record", func(r fakeRequest) bool {
			return r.method == http.MethodPost && r.path == "transit/keys/app-r.2/metadata"
		}},
		{"clear", func(r fakeRequest) bool { return isMetadataWrite(r, "app-r", "delete", entryPending) }},
		{"commit", func(r fakeRequest) bool { return isMetadataWrite(r, "app-r", "claim", entryCurrent) }},
		{"link", func(r fakeRequest) bool {
			return isMetadataWrite(r, "app-r", "link", linkEntry(kmiplib.LinkTypeReplacementObjectLink))
		}},
	}
	for _, b := range boundaries {
		for _, applied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s applied=%t", b.name, applied), func(t *testing.T) {
				bao, m := transitBao(t)
				ctx, _ := newTestSession(t, bao, Config{})
				newRekeyKey(t, ctx)

				m.failOnce(b.match, applied)
				_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
				require.ErrorContains(t, err, "status 500")

				id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
				if b.name == "link" && applied {
					// Only the answer was lost: the ReKey had completed.
					requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `ReKey replaced it with "app-r.2"`)
				} else {
					require.NoError(t, err)
					require.Equal(t, "app-r.2", id)
				}
				requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
				require.Equal(t, []string{"app-r.2"}, m.record("app-r")[entryCurrent])
				require.Equal(t, []string{"app-r", "app-r.2"}, m.keys())
			})
		}
	}
}

// A create that transit refuses, as a role without update on the
// successor's name gets, did not run. The marker must go with it: left in
// place, it would let a key an operator creates under that name at any later
// time be adopted as the replacement.
func TestTranslator_RekeyRefusedCreateClearsMarker(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	m.mu.Lock()
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		if r.method == http.MethodPost && r.path == "transit/keys/app-r.2" {
			return http.StatusForbidden, withErrors("permission denied")
		}
		return serve()
	}
	m.mu.Unlock()
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.Error(t, err)
	require.Empty(t, m.record("app-r")[entryPending])

	// Later, an operator makes a key of the same type under that name.
	m.mu.Lock()
	m.intercept = nil
	m.mu.Unlock()
	m.createKey("app-r.2")

	_, err = op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.ErrorContains(t, err, "app-r.2")
	require.Empty(t, m.record("app-r.2"), "the operator's key was adopted")
	// No ReKey committed, so the Name never moved.
	require.Empty(t, m.record("app-r")[entryCurrent])
}

// The first generation of a rekeyed Name holds the record that resolves the
// Name. Destroy keeps the key and its record, so destroying that generation
// loses nothing: Locate by Name still finds the current generation, even
// with deletion_allowed set.
func TestTranslator_DestroyKeepsAnchorOfRekeyedName(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.2", id)
	status, raw := m.do(http.MethodPost, "keys/app-r/config", map[string]any{"deletion_allowed": true})
	require.Equal(t, http.StatusOK, status, string(raw))

	// The replaced anchor is Deactivated, so Destroy accepts it.
	require.NoError(t, op(t, ctx).destroy(ctx, "app-r"))
	anchor := m.key("app-r")
	require.NotNil(t, anchor, "the anchor was deleted")
	require.True(t, anchor.SoftDeleted)
	require.Equal(t, kmiplib.StateDestroyed, anchor.state())
	require.Equal(t, []string{"app-r.2"}, anchor.entry(entryCurrent))
	require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-r"))

	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-r"},
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"app-r.2"}, ids)

	// The Name moves on as before.
	id, err = op(t, ctx).rekey(ctx, "app-r.2", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.3", id)
	requireRekeyed(t, m, "app-r", "app-r.2", "app-r.3", 3)
}

// A ReKey that committed and then failed to link the predecessor is
// repaired by a retry, also after the Name moved past its replacement. The
// retry leaves the Name where it is.
func TestTranslator_RekeyRepairsLinkAfterNameMoved(t *testing.T) {
	bao, m := transitBao(t)
	bao.metadata["kmip_rekey_retain"] = "3"
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	m.failOnce(func(r fakeRequest) bool {
		return isMetadataWrite(r, "app-r", "link", linkEntry(kmiplib.LinkTypeReplacementObjectLink))
	}, false)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.ErrorContains(t, err, "status 500")

	// The Name already resolves to the replacement, and a client rekeys it.
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-r"},
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"app-r.2"}, ids)
	id, err := op(t, ctx).rekey(ctx, "app-r.2", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.3", id)

	// Without its link, the predecessor still has the Name and is Active.
	attrs, err := op(t, ctx).getAttributes(ctx, "app-r", nil)
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateActive)
	require.Len(t, attrsNamed(attrs, kmiplib.AttributeNameName), 1)

	start := len(bao.all())
	id, err = op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.2", id)
	sent := since(bao, start)
	require.NotContains(t, sent, "POST transit/keys/app-r.2")
	require.NotContains(t, sent, "POST transit/keys/app-r.2/metadata")
	for _, r := range sent {
		require.NotContains(t, r, "soft-delete")
	}

	requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	requireRekeyed(t, m, "app-r", "app-r.2", "app-r.3", 3)
	require.Equal(t, []string{"app-r.3"}, m.record("app-r")[entryCurrent])
	require.Equal(t, []string{"app-r", "app-r.2", "app-r.3"}, m.keys())

	attrs, err = op(t, ctx).getAttributes(ctx, "app-r", nil)
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateDeactivated)
	require.Empty(t, attrsNamed(attrs, kmiplib.AttributeNameName))
}

// With kmip_rekey_retain=2, the sweep of the next ReKey soft-deletes a
// predecessor that an interrupted ReKey committed and did not link. Without
// the repair, a retry fails on the soft-deleted key and the predecessor never
// gets the link a client holding its UID needs.
func TestTranslator_RekeyRepairsLinkAfterSweep(t *testing.T) {
	bao, m := transitBao(t)
	bao.metadata["kmip_rekey_retain"] = "2"
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	m.failOnce(func(r fakeRequest) bool {
		return isMetadataWrite(r, "app-r", "link", linkEntry(kmiplib.LinkTypeReplacementObjectLink))
	}, false)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.ErrorContains(t, err, "status 500")

	id, err := op(t, ctx).rekey(ctx, "app-r.2", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.3", id)

	// The sweep reached the predecessor before its link was written.
	pred := m.key("app-r")
	require.True(t, pred.SoftDeleted)
	require.Empty(t, pred.replacement())

	start := len(bao.all())
	id, err = op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.2", id)
	// Only the link is written: nothing is created, nothing is swept, and the
	// Name does not move back.
	sent := since(bao, start)
	require.NotContains(t, sent, "POST transit/keys/app-r.2")
	require.NotContains(t, sent, "POST transit/keys/app-r.2/metadata")
	for _, r := range sent {
		require.NotContains(t, r, "soft-delete")
	}
	require.Equal(t, "app-r.2", m.key("app-r").replacement())
	require.Equal(t, []string{"app-r.3"}, m.record("app-r")[entryCurrent])

	// A client holding the predecessor's UID can follow the link.
	attrs, err := op(t, ctx).getAttributes(ctx, "app-r", nil)
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StateDeactivated)
	found := false
	for _, a := range attrsNamed(attrs, kmiplib.AttributeNameLink) {
		if l := a.AttributeValue.(kmiplib.Link); l.LinkType == kmiplib.LinkTypeReplacementObjectLink {
			require.Equal(t, "app-r.2", l.LinkedObjectIdentifier)
			found = true
		}
	}
	require.True(t, found, "predecessor has no ReplacementObjectLink")

	// The repair is done; a second retry does not replace the key again.
	_, err = op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.Error(t, err)
}

// Two ReKeys of one key can interleave so that this one read P before the
// other marked and created S, and then finds S without a record. S is the
// other ReKey's replacement, not a foreign key: this one adopts or resumes
// it. Calling it foreign told an operator to delete the key that then held
// the Name.
func TestTranslator_RekeyRaceFindsUnrecordedSuccessor(t *testing.T) {
	// recordS writes S's record and clears P's marker, as the other ReKey's
	// next two steps do.
	recordS := func(m *transitMount) {
		ops := replaceOps(entryAnchor, "app-r")
		ops = append(ops, replaceOps(entryGeneration, "2")...)
		ops = append(ops, replaceOps(linkEntry(kmiplib.LinkTypeReplacedObjectLink), "app-r")...)
		for entry, values := range m.record("app-r") {
			if strings.HasPrefix(entry, entryAttrPrefix) {
				ops = append(ops, replaceOps(entry, values...)...)
			}
		}
		m.write("app-r.2", ops...)
		m.write("app-r", deleteOp(entryPending))
	}
	for _, tc := range []struct {
		name string
		// recorded: the other ReKey also writes S's record and clears its
		// marker after this one finds S without a record.
		recorded bool
	}{{"marker still set", false}, {"record written since", true}} {
		t.Run(tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			newRekeyKey(t, ctx)

			var readP, readS sync.Once
			m.mu.Lock()
			m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
				status, out := serve()
				switch {
				case r.method == http.MethodGet && r.path == "transit/keys/app-r/metadata":
					readP.Do(func() {
						m.write("app-r", claimOp(entryPending, "app-r.2", ""))
						m.createKey("app-r.2")
					})
				case tc.recorded && r.method == http.MethodGet && r.path == "transit/keys/app-r.2/metadata":
					readS.Do(func() { recordS(m) })
				}
				return status, out
			}
			m.mu.Unlock()

			id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
			require.NoError(t, err)
			require.Equal(t, "app-r.2", id)
			requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
		})
	}
}

// Locate's read of the current generation follows a read of the anchor
// that succeeded with the same token, so a 403 on it is a denial. It must
// not revoke the token and log in again.
func TestTranslator_LocateDeniedSuccessorReadDoesNotLogIn(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)

	m.mu.Lock()
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		if r.method == http.MethodGet && r.path == "transit/keys/app-r.2" {
			return http.StatusForbidden, withErrors("permission denied")
		}
		return serve()
	}
	m.mu.Unlock()

	start := len(bao.all())
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-r"},
	}})
	require.NoError(t, err)
	require.Empty(t, ids)
	for _, r := range since(bao, start) {
		require.NotContains(t, r, "login")
	}
	require.Equal(t, []string{"GET transit/keys/app-r", "GET transit/keys/app-r/metadata", "GET transit/keys/app-r.2"}, since(bao, start))
}

// Between creating its replacement and writing the replacement's record,
// ReKey must not see that key written to: the record would replace the
// write, or a retry would take the key for a foreign one.
func TestTranslator_AddAttributeRefusesUninitializedSuccessor(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	// An earlier ReKey created S and stopped before its record.
	m.write("app-r", claimOp(entryPending, "app-r.2", ""))
	m.createKey("app-r.2")

	start := len(bao.all())
	_, err := op(t, ctx).addAttributeAt(ctx, "app-r.2", customAttr("x-tag", "green"))
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "still being created")
	require.NotContains(t, since(bao, start), "POST transit/keys/app-r.2/metadata")
	require.Empty(t, m.record("app-r.2"))

	// The retry still adopts S.
	id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "app-r.2", id)
	requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
}

// A transit key whose name only looks like a ReKey replacement takes
// attributes like any other key: its predecessor is missing, is not a key of
// the right shape, or does not name it as pending.
func TestTranslator_AddAttributeOnDottedDigitsKey(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("svc")
	for _, name := range []string{
		"db.2024",  // predecessor db.2023 is missing
		"orders.1", // generation 1 is never a replacement
		"app.2",    // predecessor app is missing
		"svc.2",    // predecessor svc exists and names nothing
	} {
		m.createKey(name)
		_, err := op(t, ctx).addAttributeAt(ctx, name, customAttr("x-tag", "blue"))
		require.NoError(t, err, name)
		require.NotEmpty(t, m.record(name)[attrEntry("x-tag")], name)
	}
}

// A key restored under a new name is an object of its own. It must not take
// the KMIP identity of the key it was backed up from: Locate for the new Name
// would follow that key's current pointer and return its current generation,
// and a client would encrypt with the wrong key.
func TestTranslator_RestoreUnderNewNameIsItsOwnObject(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)

	status, raw := m.do(http.MethodPost, "keys/app-r/config", map[string]any{"allow_plaintext_backup": true})
	require.Equal(t, http.StatusOK, status, string(raw))
	status, raw = m.do(http.MethodGet, "backup/app-r", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var backup struct {
		Data struct {
			Backup string `json:"backup"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &backup))
	status, raw = m.do(http.MethodPost, "restore/app-b", map[string]any{"backup": backup.Data.Backup})
	require.Equal(t, http.StatusNoContent, status, string(raw))

	require.Empty(t, m.record("app-b"))
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{
		AttributeName:  kmiplib.AttributeNameName,
		AttributeValue: kmiplib.Name{NameValue: "app-b"},
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"app-b"}, ids)
}

// One malformed kmip/ value, which any client with update on a key's metadata
// may write, must not fail a Locate scan for the whole mount: the scan skips
// that key, as it skips a key it may not read.
func TestTranslator_LocateSkipsUndecodableMetadata(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	for _, name := range []string{"app-a", "app-b"} {
		_, err := op(t, ctx).create(ctx, name, kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)
		_, err = op(t, ctx).addAttributeAt(ctx, name, customAttr("x-tag", "blue"))
		require.NoError(t, err)
	}

	// An operator writes app-b's current as a plain string, not a JSON array.
	status, raw := m.do(http.MethodGet, "keys/app-b/metadata", nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var stored struct {
		Data struct {
			Version uint64            `json:"version"`
			Map     map[string]string `json:"custom_metadata"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &stored))
	data := map[string]any{"kmip/current": "app-b.3"}
	for k, v := range stored.Data.Map {
		if k != "kmip/current" {
			data[k] = v
		}
	}
	status, raw = m.do(http.MethodPost, "keys/app-b/metadata", map[string]any{"custom_metadata": data, "cas": stored.Data.Version})
	require.Equal(t, http.StatusOK, status, string(raw))

	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{customAttr("x-tag", "blue")})
	require.NoError(t, err)
	require.Equal(t, []string{"app-a"}, ids)
}

// A key whose metadata was stored in the unreleased draft shape takes new
// attributes over KMIP: the draft record reads as absent, instead of failing
// every check-and-set and telling the client to retry forever.
func TestTranslator_AddAttributeOverDraftRecord(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	m.createKey("draft")
	require.NoError(t, m.storage.Put(t.Context(), &logical.StorageEntry{
		Key:   "metadata/draft",
		Value: []byte(`{"kmip":{"attr:x-tag":["old"]}}`),
	}))

	_, err := op(t, ctx).addAttributeAt(ctx, "draft", customAttr("x-color", "blue"))
	require.NoError(t, err)
	require.NotEmpty(t, m.record("draft")[attrEntry("x-color")])
}

// A ReKey whose Name holds an object that is not a later generation fails
// at the commit and does not link the predecessor.
func TestTranslator_RekeyNameHeldByAnotherObject(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	m.write("app-r", claimOp(entryCurrent, "app-other", ""))

	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `object "app-r" is no longer the current object of the Name "app-r"`)
	require.NotContains(t, m.record("app-r"), linkEntry(kmiplib.LinkTypeReplacementObjectLink))
	require.Equal(t, []string{"app-other"}, m.record("app-r")[entryCurrent])
}

// A ReKey that read the key before a concurrent ReKey of it completed
// keeps the replacement's record, and the attributes added to it since.
func TestTranslator_RekeyStaleRequestKeepsSuccessorRecord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match func(fakeRequest) bool
		// staleWrites is how many writes to the replacement's record the
		// stale ReKey sends. None applies.
		staleWrites int
	}{
		// The stale ReKey finds the replacement's record when it reads it.
		{"before reading the replacement", func(r fakeRequest) bool {
			return r.method == http.MethodGet && r.path == "transit/keys/app-r.2"
		}, 0},
		// The stale ReKey created the replacement; the other ReKey adopts it
		// and writes its record first.
		{"before writing its record", func(r fakeRequest) bool {
			return r.method == http.MethodPost && r.path == "transit/keys/app-r.2/metadata"
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			newRekeyKey(t, ctx)

			staleCtx, stale := newTestSession(t, bao, Config{})
			_, err := op(t, staleCtx).getAttributeList(staleCtx, "app-r")
			require.NoError(t, err)
			stale.mu.Lock()
			token := stale.token
			stale.mu.Unlock()
			reached, release := m.pauseAt(token, tc.match)
			resume := sync.OnceFunc(func() { close(release) })
			defer resume()

			staleOp := op(t, staleCtx)
			var staleID string
			var staleErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				staleID, staleErr = staleOp.rekey(staleCtx, "app-r", nil, nil)
			}()
			select {
			case <-reached:
			case <-done:
				t.Fatalf("the stale ReKey did not pause: %v", staleErr)
			}

			id, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
			require.NoError(t, err)
			require.Equal(t, "app-r.2", id)
			require.NoError(t, op(t, ctx).addAttribute(ctx, "app-r.2", customAttr("x-tag", "green")))

			resume()
			<-done
			require.NoError(t, staleErr)
			require.Equal(t, "app-r.2", staleID)

			attrs, err := op(t, ctx).getAttributes(ctx, "app-r.2", []kmiplib.AttributeName{"x-tag"})
			require.NoError(t, err)
			tags := attrsNamed(attrs, "x-tag")
			require.Len(t, tags, 2)
			require.True(t, slices.ContainsFunc(tags, func(a kmiplib.Attribute) bool {
				return sameValue(customAttr("x-tag", "green"), a)
			}))

			staleWrites := 0
			for _, r := range bao.sent(http.MethodPost, "transit/keys/app-r.2/metadata") {
				if r.token == token {
					staleWrites++
				}
			}
			require.Equal(t, tc.staleWrites, staleWrites)

			p := m.record("app-r")
			require.Equal(t, []string{"app-r.2"}, p[linkEntry(kmiplib.LinkTypeReplacementObjectLink)])
			require.Equal(t, []string{"app-r.2"}, p[entryCurrent])
			require.NotContains(t, p, entryPending)
			require.Equal(t, []string{"app-r", "app-r.2"}, m.keys())
		})
	}
}

// Concurrent ReKeys of one key make one replacement, with one instance of
// each attribute.
func TestTranslator_RekeyConcurrentSameKey(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	const n = 8
	calls := make([]*call, n)
	ctxs := make([]context.Context, n)
	for i := range n {
		ctxs[i], _ = newTestSession(t, bao, Config{})
		calls[i] = op(t, ctxs[i])
	}

	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			ids[i], errs[i] = calls[i].rekey(ctxs[i], "app-r", nil, nil)
		})
	}
	wg.Wait()

	succeeded := 0
	for i := range n {
		if errs[i] != nil {
			// A ReKey that lost the race fails cleanly and names why. It is
			// never told the replacement is foreign: following that advice
			// would delete the key that holds the Name.
			require.Regexp(t, `ReKey replaced it with "app-r.2"`, errs[i].Error())
			continue
		}
		succeeded++
		require.Equal(t, "app-r.2", ids[i])
	}
	require.Positive(t, succeeded)
	requireRekeyed(t, m, "app-r", "app-r", "app-r.2", 2)
	require.Equal(t, []string{"app-r.2"}, m.record("app-r")[entryCurrent])
	require.Equal(t, []string{"app-r", "app-r.2"}, m.keys())
}

// Clients that each rekey whatever the Name currently resolves to never
// move the Name back to an older generation, and every generation links to
// the next exactly once.
func TestTranslator_RekeyConcurrentChain(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)

	var mu sync.Mutex
	var currents []int
	m.storage.mu.Lock()
	m.storage.onPut = func(entry *logical.StorageEntry) {
		if entry.Key != "metadata/app-r" {
			return
		}
		var stored struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(entry.Value, &stored); err != nil {
			return
		}
		record, err := decodeMetadata(stored.Data)
		if err != nil {
			return
		}
		if current := record[metadataScope][entryCurrent]; len(current) == 1 {
			gen, _ := strconv.Atoi(strings.TrimPrefix(current[0], "app-r."))
			mu.Lock()
			currents = append(currents, gen)
			mu.Unlock()
		}
	}
	m.storage.mu.Unlock()

	const clients, rounds = 4, 5
	calls := make([][]*call, clients)
	ctxs := make([]context.Context, clients)
	for i := range clients {
		ctxs[i], _ = newTestSession(t, bao, Config{})
		for range 2 * rounds {
			calls[i] = append(calls[i], op(t, ctxs[i]))
		}
	}
	byName := []kmiplib.Attribute{{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-r"}}}

	var wg sync.WaitGroup
	for i := range clients {
		wg.Go(func() {
			for r := range rounds {
				ids, err := calls[i][2*r].locate(ctxs[i], byName)
				if err != nil || len(ids) != 1 {
					t.Errorf("locate: %v %v", ids, err)
					return
				}
				_, _ = calls[i][2*r+1].rekey(ctxs[i], ids[0], nil, nil)
			}
		})
	}
	wg.Wait()

	require.NotEmpty(t, currents)
	require.True(t, slices.IsSorted(currents), "the Name moved back: %v", currents)

	newest := currents[len(currents)-1]
	require.Equal(t, []string{"app-r." + strconv.Itoa(newest)}, m.record("app-r")[entryCurrent])
	want := []string{"app-r"}
	for gen := 2; gen <= newest; gen++ {
		pred := "app-r"
		if gen > 2 {
			pred = "app-r." + strconv.Itoa(gen-1)
		}
		requireRekeyed(t, m, "app-r", pred, "app-r."+strconv.Itoa(gen), gen)
		want = append(want, "app-r."+strconv.Itoa(gen))
	}
	slices.Sort(want)
	require.Equal(t, want, m.keys())
}

func TestTranslator_LocateByStoredAttribute(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	for name, tag := range map[string]string{"app-a": "blue", "app-b": "red"} {
		_, err := op(t, ctx).create(ctx, name, kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)
		require.NoError(t, op(t, ctx).addAttribute(ctx, name, customAttr("x-tag", tag)))
	}
	_, err := op(t, ctx).create(ctx, "app-c", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)

	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{customAttr("x-tag", "blue")})
	require.NoError(t, err)
	require.Equal(t, []string{"app-a"}, ids)

	ids, err = op(t, ctx).locate(ctx, []kmiplib.Attribute{
		customAttr("x-tag", "red"),
		{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: kmiplib.ObjectTypeSymmetricKey},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"app-b"}, ids)
}

// The adapter replays its operation against the newer record after a CAS
// mismatch. The failed POST must not append the attribute twice.
func TestTranslator_MetadataCASRetry(t *testing.T) {
	bao, m := transitBao(t)
	m.createKey("k")
	status, raw := m.do(http.MethodPost, "keys/k/metadata", map[string]any{"custom_metadata": map[string]string{"other/owner": "keep"}})
	require.Equal(t, http.StatusOK, status, string(raw))
	ctx, _ := newTestSession(t, bao, Config{})
	var once sync.Once
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		if r.method == http.MethodPost && r.path == "transit/keys/k/metadata" {
			once.Do(func() { m.write("k", addOp("attr/x-tag", encodeAttr(customAttr("x-tag", "concurrent")))) })
		}
		return serve()
	}
	index, err := op(t, ctx).addAttributeAt(ctx, "k", customAttr("x-tag", "mine"))
	require.NoError(t, err)
	require.Equal(t, int32(1), index)
	require.Len(t, bao.sent(http.MethodPost, "transit/keys/k/metadata"), 2)
	require.Equal(t, []string{encodeAttr(customAttr("x-tag", "concurrent")), encodeAttr(customAttr("x-tag", "mine"))}, m.record("k")["attr/x-tag"])
	status, raw = m.do(http.MethodGet, "keys/k/metadata", nil)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(raw), `"other/owner":"keep"`)
}

func TestTranslator_MetadataCASRetryLimit(t *testing.T) {
	bao, m := transitBao(t)
	m.createKey("k")
	ctx, _ := newTestSession(t, bao, Config{})
	m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
		if r.method == http.MethodPost && r.path == "transit/keys/k/metadata" {
			m.write("k", addOp("other", "concurrent"))
		}
		return serve()
	}
	_, err := op(t, ctx).writeMetadata(ctx, "k", addOp("mine", "once"))
	requireReason(t, err, kmiplib.ResultReasonGeneralFailure, "record kept changing; retry")
	require.Len(t, bao.sent(http.MethodGet, "transit/keys/k/metadata"), 8)
	require.Len(t, bao.sent(http.MethodPost, "transit/keys/k/metadata"), 8)
	require.NotContains(t, m.record("k"), "mine")
	require.Len(t, m.record("k")["other"], 8)
}

func TestTranslator_MetadataReadDenied(t *testing.T) {
	bao, m := transitBao(t)
	m.createKey("k")
	bao.route(http.MethodGet, "transit/keys/k/metadata", respond(http.StatusForbidden, withErrors("permission denied")))
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).getAttributes(ctx, "k", nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `GET transit/keys/k/metadata requires the "read" capability`)
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{customAttr("x-tag", "blue")})
	require.NoError(t, err)
	require.Empty(t, ids)
	m.createKey("k.2")
	pending, err := op(t, ctx).pendingSuccessor(ctx, "k.2")
	require.NoError(t, err)
	require.False(t, pending)
}

func TestTranslator_MetadataRecord(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `"x"`, `1`, `[1]`} {
		_, err := decodeMetadata(map[string]string{"kmip/bad": raw, "owner": "keep"})
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `metadata key "kmip/bad"`)
	}
	record, err := decodeMetadata(map[string]string{"kmip/a": `["1","2"]`, "owner": "keep"})
	require.NoError(t, err)
	require.Equal(t, metadataRecord{metadataScope: {"a": {"1", "2"}}}, record)
	require.ErrorContains(t, record.apply(linkOp("link", "../bad")), "not a key name")
	require.NoError(t, record.apply(claimOp("owner", "one", "")))
	err = record.apply(claimOp("owner", "two", ""))
	require.ErrorIs(t, err, errClaimHeld)
	require.ErrorContains(t, err, `is held by "one"`)
	require.NoError(t, record.apply(claimOp("owner", "two", "one")))
	require.Equal(t, []string{"two"}, record[metadataScope]["owner"])
}

func TestTranslator_RekeyRetainAll(t *testing.T) {
	for _, retain := range []string{"", "0", "invalid", "-1"} {
		t.Run("retain="+retain, func(t *testing.T) {
			bao, m := transitBao(t)
			if retain != "" {
				bao.metadata["kmip_rekey_retain"] = retain
			}
			ctx, s := newTestSession(t, bao, Config{})
			newRekeyKey(t, ctx)
			value, err := s.rekeyRetain(ctx)
			require.NoError(t, err)
			require.Zero(t, value)
			uid := "app-r"
			for range 3 {
				uid, err = op(t, ctx).rekey(ctx, uid, nil, nil)
				require.NoError(t, err)
			}
			for _, uid := range []string{"app-r", "app-r.2", "app-r.3", "app-r.4"} {
				require.False(t, m.key(uid).SoftDeleted)
				obj, err := op(t, ctx).get(ctx, uid)
				require.NoError(t, err)
				key, ok := obj.(*kmiplib.SymmetricKey)
				require.True(t, ok)
				require.NotNil(t, key.KeyBlock.KeyValue)
				require.NotNil(t, key.KeyBlock.KeyValue.Plain)
				require.NotNil(t, key.KeyBlock.KeyValue.Plain.KeyMaterial.Bytes)
				require.Len(t, *key.KeyBlock.KeyValue.Plain.KeyMaterial.Bytes, 32)
				require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/"+uid+"/soft-delete"))
			}
		})
	}
}

func dateAttr(name kmiplib.AttributeName, at time.Time) kmiplib.Attribute {
	return kmiplib.Attribute{AttributeName: name, AttributeValue: at}
}

func templateOf(attrs ...kmiplib.Attribute) *kmiplib.TemplateAttribute {
	return &kmiplib.TemplateAttribute{Attribute: attrs}
}

// attrOf returns the value of the only instance of name that uid has.
func attrOf(t *testing.T, ctx context.Context, uid string, name kmiplib.AttributeName) any {
	t.Helper()
	attrs, err := op(t, ctx).getAttributes(ctx, uid, []kmiplib.AttributeName{name})
	require.NoError(t, err)
	got := attrsNamed(attrs, name)
	require.Len(t, got, 1, "instances of %s on %s", name, uid)
	return got[0].AttributeValue
}

// requireDate checks that uid's only instance of name is the date want, to
// the second, which is all KMIP keeps.
func requireDate(t *testing.T, ctx context.Context, uid string, name kmiplib.AttributeName, want time.Time) {
	t.Helper()
	got, ok := attrOf(t, ctx, uid, name).(time.Time)
	require.True(t, ok, "%s is not a date", name)
	require.Equal(t, want.Unix(), got.Unix(), "%s", name)
}

// requireRecent checks that uid's only instance of name is a date close to
// now.
func requireRecent(t *testing.T, ctx context.Context, uid string, name kmiplib.AttributeName) time.Time {
	t.Helper()
	got, ok := attrOf(t, ctx, uid, name).(time.Time)
	require.True(t, ok, "%s is not a date", name)
	require.WithinDuration(t, time.Now(), got, 10*time.Second, "%s", name)
	return got
}

// newPreActive creates the AES key uid through KMIP with an Activation Date
// an hour ahead.
func newPreActive(t *testing.T, ctx context.Context, uid string) {
	t.Helper()
	_, err := op(t, ctx).create(ctx, uid, kmiplib.CryptographicAlgorithmAES, 256,
		templateOf(dateAttr(kmiplib.AttributeNameActivationDate, time.Now().Add(time.Hour))))
	require.NoError(t, err)
	require.Equal(t, kmiplib.StatePreActive, attrOf(t, ctx, uid, kmiplib.AttributeNameState))
}

// Every row of the State precedence, from the record and the transit key
// alone.
func TestKeyInfo_State(t *testing.T) {
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	mark := func(entry string) map[string][]string { return map[string][]string{entry: {markSet}} }
	date := func(name kmiplib.AttributeName, at time.Time) map[string][]string {
		return map[string][]string{attrEntry(name): {encodeAttr(dateAttr(name, at))}}
	}
	join := func(parts ...map[string][]string) map[string][]string {
		out := map[string][]string{}
		for _, part := range parts {
			maps.Copy(out, part)
		}
		return out
	}
	replaced := map[string][]string{linkEntry(kmiplib.LinkTypeReplacementObjectLink): {"k.2"}}

	cases := []struct {
		name        string
		softDeleted bool
		entries     map[string][]string
		want        kmiplib.State
	}{
		{"new key", false, nil, kmiplib.StateActive},
		{"destroy mark", true, mark(entryDestroyed), kmiplib.StateDestroyed},
		{"destroy mark on a key that is not soft-deleted", false, mark(entryDestroyed), kmiplib.StateDestroyed},
		{"destroy and compromise marks", true, join(mark(entryDestroyed), mark(entryCompromised)), kmiplib.StateDestroyedCompromised},
		{"destroy mark before a future activation", true, join(mark(entryDestroyed), date(kmiplib.AttributeNameActivationDate, future)), kmiplib.StateDestroyed},
		{"compromise mark", false, mark(entryCompromised), kmiplib.StateCompromised},
		{"compromise mark on a soft-deleted key", true, mark(entryCompromised), kmiplib.StateCompromised},
		{"compromise mark on a replaced key", false, join(mark(entryCompromised), replaced), kmiplib.StateCompromised},
		{"soft-deleted", true, nil, kmiplib.StateDeactivated},
		{"soft-deleted before a future activation", true, date(kmiplib.AttributeNameActivationDate, future), kmiplib.StateDeactivated},
		{"replaced by ReKey", false, replaced, kmiplib.StateDeactivated},
		{"past deactivation date", false, date(kmiplib.AttributeNameDeactivationDate, past), kmiplib.StateDeactivated},
		{"past deactivation before a future activation", false, join(date(kmiplib.AttributeNameDeactivationDate, past), date(kmiplib.AttributeNameActivationDate, future)), kmiplib.StateDeactivated},
		{"future deactivation date", false, date(kmiplib.AttributeNameDeactivationDate, future), kmiplib.StateActive},
		{"future activation date", false, date(kmiplib.AttributeNameActivationDate, future), kmiplib.StatePreActive},
		{"future activation and deactivation dates", false, join(date(kmiplib.AttributeNameActivationDate, future), date(kmiplib.AttributeNameDeactivationDate, future.Add(time.Hour))), kmiplib.StatePreActive},
		{"past activation date", false, date(kmiplib.AttributeNameActivationDate, past), kmiplib.StateActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &keyInfo{Name: "k", SoftDeleted: tc.softDeleted}
			if tc.entries != nil {
				info.Metadata = metadataRecord{metadataScope: tc.entries}
			}
			require.Equal(t, tc.want, info.state())
			state, err := info.checkedState()
			require.NoError(t, err)
			require.Equal(t, tc.want, state)
		})
	}
}

// A stored Activation Date or Deactivation Date that is not one date fails
// checkedState. state reports the State as if the date were absent.
func TestKeyInfo_CheckedStateRefusesBadDates(t *testing.T) {
	future := time.Now().Add(time.Hour)
	activation, deactivation := attrEntry(kmiplib.AttributeNameActivationDate), attrEntry(kmiplib.AttributeNameDeactivationDate)
	mask := encodeAttr(kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt})

	cases := []struct {
		name    string
		entries map[string][]string
		msg     string
	}{
		{"undecodable activation date", map[string][]string{activation: {"not ttlv"}}, `object "k" has an undecodable stored attribute`},
		{"undecodable deactivation date", map[string][]string{deactivation: {"not ttlv"}}, `object "k" has an undecodable stored attribute`},
		{"activation date that is not a date", map[string][]string{activation: {mask}}, `object "k" has a stored Activation Date that is not a date`},
		{"deactivation date stored as another date", map[string][]string{deactivation: {encodeAttr(dateAttr(kmiplib.AttributeNameActivationDate, future))}}, `object "k" has a stored Deactivation Date that is not a date`},
		{"two activation dates", map[string][]string{activation: {encodeAttr(dateAttr(kmiplib.AttributeNameActivationDate, future)), encodeAttr(dateAttr(kmiplib.AttributeNameActivationDate, future))}}, `object "k" stores 2 values of the single-instance attribute Activation Date`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &keyInfo{Name: "k", Metadata: metadataRecord{metadataScope: tc.entries}}
			_, err := info.checkedState()
			requireReason(t, err, kmiplib.ResultReasonGeneralFailure, tc.msg)
			require.Equal(t, kmiplib.StateActive, info.state())
		})
	}
}

// Activate fails on a stored lifecycle date that does not decode, whether
// the first read finds it or a concurrent write puts it there before the
// write of the Activation Date.
func TestTranslator_ActivateRefusesBadDates(t *testing.T) {
	for _, name := range []kmiplib.AttributeName{kmiplib.AttributeNameActivationDate, kmiplib.AttributeNameDeactivationDate} {
		corrupt := replaceOps(attrEntry(name), "not ttlv")

		t.Run(string(name)+" on the first read", func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
			require.NoError(t, err)
			m.write("app-a", corrupt...)

			err = op(t, ctx).activate(ctx, "app-a")
			requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `object "app-a" has an undecodable stored attribute`)
			require.Empty(t, bao.sent(http.MethodPost, "transit/keys/app-a/metadata"))
		})

		t.Run(string(name)+" on a write attempt", func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			newPreActive(t, ctx, "app-a")
			var once sync.Once
			m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
				if r.method == http.MethodPost && r.path == "transit/keys/app-a/metadata" {
					once.Do(func() { m.write("app-a", corrupt...) })
				}
				return serve()
			}

			err := op(t, ctx).activate(ctx, "app-a")
			requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `object "app-a" has an undecodable stored attribute`)
			require.Len(t, bao.sent(http.MethodPost, "transit/keys/app-a/metadata"), 2)
			require.Equal(t, []string{"not ttlv"}, m.record("app-a")[attrEntry(name)])
		})
	}
}

// Locate's State filter matches the derived states.
func TestTranslator_LocateByState(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).create(ctx, "app-active", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	newPreActive(t, ctx, "app-pre")
	_, err = op(t, ctx).create(ctx, "app-dated", kmiplib.CryptographicAlgorithmAES, 256,
		templateOf(dateAttr(kmiplib.AttributeNameDeactivationDate, time.Now().Add(-time.Hour))))
	require.NoError(t, err)
	_, err = op(t, ctx).create(ctx, "app-gone", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	require.NoError(t, op(t, ctx).revoke(ctx, "app-gone", kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeKeyCompromise}, nil))
	require.NoError(t, op(t, ctx).destroy(ctx, "app-gone"))

	for state, want := range map[kmiplib.State][]string{
		kmiplib.StateActive:               {"app-active"},
		kmiplib.StatePreActive:            {"app-pre"},
		kmiplib.StateDeactivated:          {"app-dated"},
		kmiplib.StateDestroyedCompromised: {"app-gone"},
		kmiplib.StateCompromised:          nil,
	} {
		ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{AttributeName: kmiplib.AttributeNameState, AttributeValue: state}})
		require.NoError(t, err)
		require.ElementsMatch(t, want, ids, ttlv.EnumStr(state))
	}
}

func TestTranslator_CreateTemplate(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	future := time.Now().Add(time.Hour)

	// A template without stored attributes sends what Create always sent.
	start := len(bao.all())
	_, err := op(t, ctx).create(ctx, "app-plain", kmiplib.CryptographicAlgorithmAES, 256, templateOf(
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: kmiplib.CryptographicAlgorithmAES},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(256)},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: kmiplib.ObjectTypeSymmetricKey},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-plain"}},
	))
	require.NoError(t, err)
	require.Equal(t, []string{"POST transit/keys/app-plain"}, since(bao, start))
	require.Empty(t, m.record("app-plain"))

	// Stored attributes go to the record in one write. A future Activation
	// Date makes the object Pre-Active.
	start = len(bao.all())
	_, err = op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, templateOf(
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt},
		dateAttr(kmiplib.AttributeNameActivationDate, future),
		customAttr("x-tag", "blue"),
		customAttr("x-tag", "green"),
	))
	require.NoError(t, err)
	require.Equal(t, []string{
		"GET transit/keys/app-a", "POST transit/keys/app-a",
		"GET transit/keys/app-a/metadata", "POST transit/keys/app-a/metadata",
	}, since(bao, start))
	attrs, err := op(t, ctx).getAttributes(ctx, "app-a", nil)
	require.NoError(t, err)
	requireAttr(t, attrs, kmiplib.AttributeNameState, kmiplib.StatePreActive)
	requireAttr(t, attrs, kmiplib.AttributeNameCryptographicUsageMask, kmiplib.CryptographicUsageEncrypt)
	require.Len(t, attrsNamed(attrs, "x-tag"), 2)
	requireDate(t, ctx, "app-a", kmiplib.AttributeNameActivationDate, future)

	// Activate makes it Active, with now as its Activation Date.
	start = len(bao.all())
	require.NoError(t, op(t, ctx).activate(ctx, "app-a"))
	require.Equal(t, []string{
		"GET transit/keys/app-a", "GET transit/keys/app-a/metadata",
		"GET transit/keys/app-a/metadata", "POST transit/keys/app-a/metadata",
	}, since(bao, start))
	require.Equal(t, kmiplib.StateActive, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
	activated := requireRecent(t, ctx, "app-a", kmiplib.AttributeNameActivationDate)

	// A second Activate succeeds and writes nothing.
	start = len(bao.all())
	require.NoError(t, op(t, ctx).activate(ctx, "app-a"))
	require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))
	requireDate(t, ctx, "app-a", kmiplib.AttributeNameActivationDate, activated)

	// Register stores its template the same way.
	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)
	_, err = op(t, ctx).register(ctx, "app-imported", kmiplib.CryptographicAlgorithmAES, 256, material, templateOf(
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageDecrypt},
	))
	require.NoError(t, err)
	require.Equal(t, kmiplib.CryptographicUsageDecrypt, attrOf(t, ctx, "app-imported", kmiplib.AttributeNameCryptographicUsageMask))
	require.Equal(t, kmiplib.StateActive, attrOf(t, ctx, "app-imported", kmiplib.AttributeNameState))
}

// A template is checked before any request.
func TestTranslator_CreateTemplateRefusals(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	cases := []struct {
		name   string
		attr   kmiplib.Attribute
		reason kmiplib.ResultReason
		msg    string
	}{
		{"derived", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameState, AttributeValue: kmiplib.StatePreActive}, kmiplib.ResultReasonPermissionDenied, "attribute State is set by the server"},
		{"server-set date", dateAttr(kmiplib.AttributeNameDestroyDate, time.Now()), kmiplib.ResultReasonPermissionDenied, "attribute Destroy Date is set by the server"},
		{"server-set reason", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameRevocationReason, AttributeValue: unspecified}, kmiplib.ResultReasonPermissionDenied, "attribute Revocation Reason is set by the server"},
		{"other length", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(128)}, kmiplib.ResultReasonInvalidField, "the template's Cryptographic Length does not match"},
		{"other object type", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: kmiplib.ObjectTypePrivateKey}, kmiplib.ResultReasonInvalidField, "the template's Object Type does not match"},
		{"second Name", kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-b"}}, kmiplib.ResultReasonInvalidField, `an object takes one Name: the template gives "app-a" and "app-b"`},
		{"no value", kmiplib.Attribute{AttributeName: "x-empty"}, kmiplib.ResultReasonInvalidField, "attribute x-empty has no value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, templateOf(tc.attr))
			requireReason(t, err, tc.reason, tc.msg)
			_, err = op(t, ctx).register(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, make([]byte, 32), templateOf(tc.attr))
			requireReason(t, err, tc.reason, tc.msg)
		})
	}
	require.Empty(t, bao.all())
}

// A Create whose metadata write fails after transit made the key does not
// report success: it soft-deletes the key and names it in the error.
func TestTranslator_CreateTemplateWriteFails(t *testing.T) {
	mask := templateOf(kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt})
	denied := respond(http.StatusForbidden, withErrors("permission denied"))
	metadataWrite := func(r fakeRequest) bool {
		return r.method == http.MethodPost && strings.HasSuffix(r.path, "/metadata")
	}

	// A Create with a Name cannot prove that no other client holds the key,
	// so a failed write fails the Create and leaves the key alone.
	t.Run("named, write denied", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.route(http.MethodPost, "transit/keys/app-a/metadata", denied)
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `Create made the key "app-a" but could not store its template attributes; the key was left in place`)
		require.ErrorContains(t, err, `POST transit/keys/app-a/metadata requires the "update" capability`)
		require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a/soft-delete"))
		require.False(t, m.key("app-a").SoftDeleted)
	})

	t.Run("named, metadata read denied", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.route(http.MethodGet, "transit/keys/app-a/metadata", denied)
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `the key was left in place`)
		require.ErrorContains(t, err, `GET transit/keys/app-a/metadata requires the "read" capability`)
		require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a/soft-delete"))
		require.False(t, m.key("app-a").SoftDeleted)
	})

	t.Run("named, write fails, then retry", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		m.failOnce(metadataWrite, false)

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, "status 500")
		require.False(t, m.key("app-a").SoftDeleted)

		// A retry finds the key and does not take it for new.
		start := len(bao.all())
		_, err = op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `key "app-a" already exists`)
		require.Equal(t, []string{"GET transit/keys/app-a"}, since(bao, start))
		require.Empty(t, m.record("app-a"))
	})

	// Another client creates the same Name between Create's key read and
	// its create, so transit hands both the one key. Create's failed write
	// must not soft-delete the other client's key.
	t.Run("named, key created concurrently", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.route(http.MethodPost, "transit/keys/app-a/metadata", denied)
		ctx, _ := newTestSession(t, bao, Config{})
		var once sync.Once
		m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
			if r.method == http.MethodPost && r.path == "transit/keys/app-a" {
				once.Do(func() { m.createKey("app-a") })
			}
			return serve()
		}

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `the key was left in place`)
		require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a/soft-delete"))
		require.False(t, m.key("app-a").SoftDeleted)
	})

	// A generated name is a fresh UUID: no other client holds the key, so a
	// failed write soft-deletes it.
	t.Run("generated name, write fails", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		m.failOnce(metadataWrite, false)

		_, err := op(t, ctx).create(ctx, "", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, "but could not store its template attributes, so the key was soft-deleted")
		var uid string
		for _, r := range bao.all() {
			if r.method == http.MethodDelete && strings.HasSuffix(r.path, "/soft-delete") {
				uid = strings.TrimSuffix(strings.TrimPrefix(r.path, "transit/keys/"), "/soft-delete")
			}
		}
		require.NotEmpty(t, uid)
		require.True(t, m.key(uid).SoftDeleted)
	})

	t.Run("generated name, write and soft-delete fail", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
			if metadataWrite(r) || (r.method == http.MethodDelete && strings.HasSuffix(r.path, "/soft-delete")) {
				return http.StatusInternalServerError, withErrors("injected failure")
			}
			return serve()
		}

		_, err := op(t, ctx).create(ctx, "", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, "soft-deleting the key also failed, so it stays Active without them")
		require.Len(t, m.keys(), 1)
		require.False(t, m.key(m.keys()[0]).SoftDeleted)
	})

	// Without the key read, nothing proves the key new: Create fails before
	// transit makes it.
	t.Run("key read denied", func(t *testing.T) {
		bao, m := transitBao(t)
		bao.route(http.MethodGet, "transit/keys/app-a", denied)
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `GET transit/keys/app-a requires the "read" capability`)
		require.Empty(t, bao.sent(http.MethodPost, "transit/keys/app-a"))
		require.Nil(t, m.key("app-a"))
	})
}

// Transit answers a create of an existing key with that key. A Create or
// Register with stored attributes refuses an existing key before it writes,
// whatever metadata grant the client holds, and never soft-deletes it.
func TestTranslator_CreateTemplateKeepsExistingKey(t *testing.T) {
	mask := templateOf(kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicUsageMask, AttributeValue: kmiplib.CryptographicUsageEncrypt})
	denied := respond(http.StatusForbidden, withErrors("permission denied"))

	cases := []struct {
		name  string
		setup func(*fakeBao)
	}{
		{"metadata granted", func(*fakeBao) {}},
		{"metadata read denied", func(bao *fakeBao) { bao.route(http.MethodGet, "transit/keys/app-a/metadata", denied) }},
		{"metadata write denied", func(bao *fakeBao) { bao.route(http.MethodPost, "transit/keys/app-a/metadata", denied) }},
	}
	for _, tc := range cases {
		t.Run("Create, "+tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			m.createKey("app-a")
			tc.setup(bao)
			ctx, _ := newTestSession(t, bao, Config{})

			start := len(bao.all())
			_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
			requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `key "app-a" already exists`)
			require.Equal(t, []string{"GET transit/keys/app-a"}, since(bao, start))
			require.False(t, m.key("app-a").SoftDeleted)
			require.Empty(t, m.record("app-a"))
		})

		t.Run("Register, "+tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			m.createKey("app-a")
			tc.setup(bao)
			ctx, _ := newTestSession(t, bao, Config{})

			_, err := op(t, ctx).register(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, make([]byte, 32), mask)
			require.ErrorContains(t, err, "status 500")
			require.Empty(t, bao.sent(http.MethodGet, "transit/keys/app-a/metadata"))
			require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a/soft-delete"))
			require.False(t, m.key("app-a").SoftDeleted)
			require.Empty(t, m.record("app-a"))
		})
	}

	// A KMIP object made between Create's key read and its create shows in
	// the record: Create fails and leaves the object alone.
	t.Run("object made after the key read", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		var once sync.Once
		m.intercept = func(r fakeRequest, serve func() (int, any)) (int, any) {
			if r.method == http.MethodPost && r.path == "transit/keys/app-a" {
				once.Do(func() {
					m.createKey("app-a")
					m.write("app-a", addOp(attrEntry("x-tag"), encodeAttr(customAttr("x-tag", "blue"))))
				})
			}
			return serve()
		}
		before := map[string][]string{attrEntry("x-tag"): {encodeAttr(customAttr("x-tag", "blue"))}}

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, mask)
		requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `key "app-a" already exists`)
		require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a/soft-delete"))
		require.False(t, m.key("app-a").SoftDeleted)
		require.Equal(t, before, m.record("app-a"))
	})
}

func TestTranslator_Revoke(t *testing.T) {
	keyCompromise := kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeKeyCompromise, RevocationMessage: "leaked"}
	caCompromise := kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeCACompromise}
	cessation := kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeCessationOfOperation}

	t.Run("deactivating reason", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)

		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", cessation, nil))
		require.True(t, m.key("app-a").SoftDeleted)
		require.Equal(t, kmiplib.StateDeactivated, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
		requireRecent(t, ctx, "app-a", kmiplib.AttributeNameDeactivationDate)
		require.Equal(t, cessation, attrOf(t, ctx, "app-a", kmiplib.AttributeNameRevocationReason))
		attrs, err := op(t, ctx).getAttributes(ctx, "app-a", []kmiplib.AttributeName{kmiplib.AttributeNameCompromiseDate, kmiplib.AttributeNameCompromiseOccurrenceDate})
		require.NoError(t, err)
		require.Empty(t, attrs)
		require.NotContains(t, m.record("app-a"), entryCompromised)
	})

	t.Run("key compromise with an occurrence date", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)

		occurred := time.Unix(1750000000, 0)
		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", keyCompromise, &occurred))
		require.True(t, m.key("app-a").SoftDeleted)
		require.Equal(t, kmiplib.StateCompromised, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
		compromised := requireRecent(t, ctx, "app-a", kmiplib.AttributeNameCompromiseDate)
		requireDate(t, ctx, "app-a", kmiplib.AttributeNameCompromiseOccurrenceDate, occurred)
		require.Equal(t, keyCompromise, attrOf(t, ctx, "app-a", kmiplib.AttributeNameRevocationReason))
		attrs, err := op(t, ctx).getAttributes(ctx, "app-a", []kmiplib.AttributeName{kmiplib.AttributeNameDeactivationDate})
		require.NoError(t, err)
		require.Empty(t, attrs)

		// A second compromise Revoke keeps the first dates.
		time.Sleep(1100 * time.Millisecond)
		later := time.Unix(1760000000, 0)
		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", caCompromise, &later))
		requireDate(t, ctx, "app-a", kmiplib.AttributeNameCompromiseDate, compromised)
		requireDate(t, ctx, "app-a", kmiplib.AttributeNameCompromiseOccurrenceDate, occurred)
		require.Equal(t, caCompromise, attrOf(t, ctx, "app-a", kmiplib.AttributeNameRevocationReason))

		// KMIP has no transition from Compromised to Deactivated.
		start := len(bao.all())
		err = op(t, ctx).revoke(ctx, "app-a", cessation, nil)
		requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `wrong key lifecycle state: object "app-a" is Compromised`)
		require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))
	})

	t.Run("CA compromise without an occurrence date", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)

		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", caCompromise, nil))
		initial, ok := m.key("app-a").initialDate()
		require.True(t, ok)
		requireDate(t, ctx, "app-a", kmiplib.AttributeNameCompromiseOccurrenceDate, initial)
		require.Equal(t, kmiplib.StateCompromised, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
	})

	t.Run("pre-active", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		newPreActive(t, ctx, "app-a")

		// Only a compromise takes a Pre-Active object out of Pre-Active.
		start := len(bao.all())
		err := op(t, ctx).revoke(ctx, "app-a", cessation, nil)
		requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "wrong key lifecycle state")
		require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))
		require.False(t, m.key("app-a").SoftDeleted)

		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", keyCompromise, nil))
		require.Equal(t, kmiplib.StateCompromised, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
		require.True(t, m.key("app-a").SoftDeleted)
	})

	// A Deactivation Date already past stays; Revoke only adds the reason and
	// the soft-delete.
	t.Run("past deactivation date", func(t *testing.T) {
		bao, m := transitBao(t)
		ctx, _ := newTestSession(t, bao, Config{})
		past := time.Unix(1750000000, 0)
		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256,
			templateOf(dateAttr(kmiplib.AttributeNameDeactivationDate, past)))
		require.NoError(t, err)
		require.Equal(t, kmiplib.StateDeactivated, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
		require.False(t, m.key("app-a").SoftDeleted)

		require.NoError(t, op(t, ctx).revoke(ctx, "app-a", cessation, nil))
		requireDate(t, ctx, "app-a", kmiplib.AttributeNameDeactivationDate, past)
		require.Equal(t, cessation, attrOf(t, ctx, "app-a", kmiplib.AttributeNameRevocationReason))
		require.True(t, m.key("app-a").SoftDeleted)
	})
}

// Revoke writes the record first. Interrupted after it, the object already
// reports the revoked State, and a retry finishes the soft-delete with the
// first dates kept.
func TestTranslator_RevokeInterrupted(t *testing.T) {
	isSoftDelete := func(r fakeRequest) bool {
		return r.method == http.MethodDelete && r.path == "transit/keys/app-a/soft-delete"
	}
	isRecordWrite := func(r fakeRequest) bool {
		return r.method == http.MethodPost && r.path == "transit/keys/app-a/metadata"
	}
	for _, tc := range []struct {
		name   string
		reason kmiplib.RevocationReasonCode
		match  func(fakeRequest) bool
		// after is the State between the failure and the retry.
		after kmiplib.State
		date  kmiplib.AttributeName
	}{
		{"compromise, soft-delete fails", kmiplib.RevocationReasonCodeKeyCompromise, isSoftDelete, kmiplib.StateCompromised, kmiplib.AttributeNameCompromiseDate},
		{"cessation, soft-delete fails", kmiplib.RevocationReasonCodeCessationOfOperation, isSoftDelete, kmiplib.StateDeactivated, kmiplib.AttributeNameDeactivationDate},
		{"compromise, record write fails", kmiplib.RevocationReasonCodeKeyCompromise, isRecordWrite, kmiplib.StateActive, kmiplib.AttributeNameCompromiseDate},
		{"cessation, record write fails", kmiplib.RevocationReasonCodeCessationOfOperation, isRecordWrite, kmiplib.StateActive, kmiplib.AttributeNameDeactivationDate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
			require.NoError(t, err)
			reason := kmiplib.RevocationReason{RevocationReasonCode: tc.reason}

			m.failOnce(tc.match, false)
			err = op(t, ctx).revoke(ctx, "app-a", reason, nil)
			require.ErrorContains(t, err, "status 500")
			require.False(t, m.key("app-a").SoftDeleted)
			require.Equal(t, tc.after, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))

			var first time.Time
			if tc.after != kmiplib.StateActive {
				first = requireRecent(t, ctx, "app-a", tc.date)
				time.Sleep(1100 * time.Millisecond)
			}
			require.NoError(t, op(t, ctx).revoke(ctx, "app-a", reason, nil))
			require.True(t, m.key("app-a").SoftDeleted)
			if tc.after != kmiplib.StateActive {
				requireDate(t, ctx, "app-a", tc.date, first)
			} else {
				requireRecent(t, ctx, "app-a", tc.date)
			}
		})
	}
}

func TestTranslator_Destroy(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	for _, uid := range []string{"app-a", "app-c"} {
		_, err := op(t, ctx).create(ctx, uid, kmiplib.CryptographicAlgorithmAES, 256, nil)
		require.NoError(t, err)
	}
	// deletion_allowed no longer lets Destroy delete anything.
	status, raw := m.do(http.MethodPost, "keys/app-a/config", map[string]any{"deletion_allowed": true})
	require.Equal(t, http.StatusOK, status, string(raw))

	// An Active object is refused, with nothing written.
	start := len(bao.all())
	err := op(t, ctx).destroy(ctx, "app-a")
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `wrong key lifecycle state: object "app-a" is Active`)
	require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))

	// After Revoke, Destroy marks it and keeps the key soft-deleted.
	require.NoError(t, op(t, ctx).revoke(ctx, "app-a", unspecified, nil))
	require.NoError(t, op(t, ctx).destroy(ctx, "app-a"))
	require.Equal(t, kmiplib.StateDestroyed, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
	destroyed := requireRecent(t, ctx, "app-a", kmiplib.AttributeNameDestroyDate)
	require.True(t, m.key("app-a").SoftDeleted)
	require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/app-a"))

	// A second Destroy succeeds and writes nothing.
	start = len(bao.all())
	require.NoError(t, op(t, ctx).destroy(ctx, "app-a"))
	require.Equal(t, []string{"GET transit/keys/app-a", "GET transit/keys/app-a/metadata"}, since(bao, start))
	requireDate(t, ctx, "app-a", kmiplib.AttributeNameDestroyDate, destroyed)

	// Get fails as for a soft-deleted key; Activate, Revoke and ReKey refuse
	// a Destroyed object.
	_, err = op(t, ctx).get(ctx, "app-a")
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "wrong key lifecycle state")
	requireReason(t, op(t, ctx).activate(ctx, "app-a"), kmiplib.ResultReasonPermissionDenied, "is Destroyed")
	requireReason(t, op(t, ctx).revoke(ctx, "app-a", kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeKeyCompromise}, nil),
		kmiplib.ResultReasonPermissionDenied, "is Destroyed")
	_, err = op(t, ctx).rekey(ctx, "app-a", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "is Destroyed")
	// The key survives, so its Name is not free for a new Create.
	_, err = op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	requireReason(t, err, kmiplib.ResultReasonGeneralFailure, `key "app-a" already exists`)

	// A Compromised object is refused by ReKey, and becomes Destroyed
	// Compromised.
	require.NoError(t, op(t, ctx).revoke(ctx, "app-c", kmiplib.RevocationReason{RevocationReasonCode: kmiplib.RevocationReasonCodeKeyCompromise}, nil))
	_, err = op(t, ctx).rekey(ctx, "app-c", nil, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "is Compromised")
	require.NoError(t, op(t, ctx).destroy(ctx, "app-c"))
	require.Equal(t, kmiplib.StateDestroyedCompromised, attrOf(t, ctx, "app-c", kmiplib.AttributeNameState))

	// A Pre-Active object is soft-deleted first, then marked.
	newPreActive(t, ctx, "app-p")
	start = len(bao.all())
	require.NoError(t, op(t, ctx).destroy(ctx, "app-p"))
	require.Equal(t, []string{
		"GET transit/keys/app-p", "GET transit/keys/app-p/metadata",
		"DELETE transit/keys/app-p/soft-delete",
		"GET transit/keys/app-p/metadata", "POST transit/keys/app-p/metadata",
	}, since(bao, start))
	require.True(t, m.key("app-p").SoftDeleted)
	require.Equal(t, kmiplib.StateDestroyed, attrOf(t, ctx, "app-p", kmiplib.AttributeNameState))
	require.Equal(t, []string{"app-a", "app-c", "app-p"}, m.keys())
}

// Destroy soft-deletes before it marks. Interrupted in between, the object
// reports Deactivated, which a retry accepts.
func TestTranslator_DestroyInterrupted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match func(fakeRequest) bool
		after kmiplib.State
	}{
		{"soft-delete fails", func(r fakeRequest) bool {
			return r.method == http.MethodDelete && r.path == "transit/keys/app-p/soft-delete"
		}, kmiplib.StatePreActive},
		{"record write fails", func(r fakeRequest) bool {
			return r.method == http.MethodPost && r.path == "transit/keys/app-p/metadata"
		}, kmiplib.StateDeactivated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bao, m := transitBao(t)
			ctx, _ := newTestSession(t, bao, Config{})
			newPreActive(t, ctx, "app-p")

			m.failOnce(tc.match, false)
			require.ErrorContains(t, op(t, ctx).destroy(ctx, "app-p"), "status 500")
			require.Equal(t, tc.after, attrOf(t, ctx, "app-p", kmiplib.AttributeNameState))
			require.NotContains(t, m.record("app-p"), entryDestroyed)

			require.NoError(t, op(t, ctx).destroy(ctx, "app-p"))
			require.True(t, m.key("app-p").SoftDeleted)
			require.Equal(t, kmiplib.StateDestroyed, attrOf(t, ctx, "app-p", kmiplib.AttributeNameState))
		})
	}
}

// Dates drive the reported State only: Encrypt with a key past its
// Deactivation Date still succeeds and sends its one request.
func TestTranslator_CryptoIgnoresDates(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", dateAttr(kmiplib.AttributeNameDeactivationDate, time.Now().Add(-time.Hour))))
	require.Equal(t, kmiplib.StateDeactivated, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))

	start := len(bao.all())
	_, err = op(t, ctx).encrypt(ctx, "app-a", []byte("data"))
	require.NoError(t, err)
	require.Equal(t, []string{"POST transit/encrypt/app-a"}, since(bao, start))
}

// newTaggedKey creates app-a with the x-tag instances values, in order.
func newTaggedKey(t *testing.T, ctx context.Context, values ...string) {
	t.Helper()
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	for _, v := range values {
		require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", customAttr("x-tag", v)))
	}
}

// requireTags checks the x-tag instances GetAttributes reports, in order,
// with their indexes.
func requireTags(t *testing.T, ctx context.Context, values ...string) {
	t.Helper()
	attrs, err := op(t, ctx).getAttributes(ctx, "app-a", []kmiplib.AttributeName{"x-tag"})
	require.NoError(t, err)
	require.Len(t, attrs, len(values))
	for i, v := range values {
		require.True(t, sameValue(customAttr("x-tag", v), attrs[i]), "instance %d is %v, want %s", i, attrs[i].AttributeValue, v)
		if i == 0 {
			require.Nil(t, attrs[i].AttributeIndex)
		} else {
			require.Equal(t, int32(i), *attrs[i].AttributeIndex)
		}
	}
}

func indexed(attr kmiplib.Attribute, index int32) kmiplib.Attribute {
	attr.AttributeIndex = &index
	return attr
}

func TestTranslator_ModifyAttribute(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newTaggedKey(t, ctx, "blue", "green", "red")

	// Without an index, the instance at index 0 changes.
	start := len(bao.all())
	got, err := op(t, ctx).modifyAttribute(ctx, "app-a", customAttr("x-tag", "cyan"))
	require.NoError(t, err)
	require.Nil(t, got.AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "cyan"), got))
	require.Equal(t, []string{
		"GET transit/keys/app-a", "GET transit/keys/app-a/metadata",
		"GET transit/keys/app-a/metadata", "POST transit/keys/app-a/metadata",
	}, since(bao, start))

	got, err = op(t, ctx).modifyAttribute(ctx, "app-a", indexed(customAttr("x-tag", "purple"), 2))
	require.NoError(t, err)
	require.Equal(t, int32(2), *got.AttributeIndex)
	requireTags(t, ctx, "cyan", "green", "purple")

	// An index with no instance is Item Not Found, as is an attribute the
	// object does not have.
	_, err = op(t, ctx).modifyAttribute(ctx, "app-a", indexed(customAttr("x-tag", "black"), 3))
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, `object "app-a" has no x-tag with Attribute Index 3`)
	_, err = op(t, ctx).modifyAttribute(ctx, "app-a", customAttr("x-none", "black"))
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, "has no x-none")
	requireTags(t, ctx, "cyan", "green", "purple")

	// The Activation Date GetAttributes supplies when none is stored can be
	// modified, which stores it; a future one makes the object Pre-Active.
	require.Empty(t, m.record("app-a")[attrEntry(kmiplib.AttributeNameActivationDate)])
	future := time.Now().Add(time.Hour)
	_, err = op(t, ctx).modifyAttribute(ctx, "app-a", dateAttr(kmiplib.AttributeNameActivationDate, future))
	require.NoError(t, err)
	requireDate(t, ctx, "app-a", kmiplib.AttributeNameActivationDate, future)
	require.Equal(t, kmiplib.StatePreActive, attrOf(t, ctx, "app-a", kmiplib.AttributeNameState))
	require.Len(t, m.record("app-a")[attrEntry(kmiplib.AttributeNameActivationDate)], 1)
}

func TestTranslator_DeleteAttribute(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newTaggedKey(t, ctx, "blue", "green", "red")

	// A later index; the instances after it move up.
	start := len(bao.all())
	index := int32(1)
	got, err := op(t, ctx).deleteAttribute(ctx, "app-a", "x-tag", &index)
	require.NoError(t, err)
	require.Equal(t, int32(1), *got.AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "green"), got))
	require.Equal(t, []string{
		"GET transit/keys/app-a", "GET transit/keys/app-a/metadata",
		"GET transit/keys/app-a/metadata", "POST transit/keys/app-a/metadata",
	}, since(bao, start))
	requireTags(t, ctx, "blue", "red")

	// Without an index, the instance at index 0 goes.
	got, err = op(t, ctx).deleteAttribute(ctx, "app-a", "x-tag", nil)
	require.NoError(t, err)
	require.Nil(t, got.AttributeIndex)
	require.True(t, sameValue(customAttr("x-tag", "blue"), got))
	requireTags(t, ctx, "red")

	index = 1
	_, err = op(t, ctx).deleteAttribute(ctx, "app-a", "x-tag", &index)
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, `object "app-a" has no x-tag with Attribute Index 1`)

	// The Activation Date GetAttributes supplies is not stored, so there is
	// nothing to delete.
	_, err = op(t, ctx).deleteAttribute(ctx, "app-a", kmiplib.AttributeNameActivationDate, nil)
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, "has no Activation Date")

	// The last instance takes the attribute with it.
	_, err = op(t, ctx).deleteAttribute(ctx, "app-a", "x-tag", nil)
	require.NoError(t, err)
	require.NotContains(t, m.record("app-a"), attrEntry("x-tag"))
	names, err := op(t, ctx).getAttributeList(ctx, "app-a")
	require.NoError(t, err)
	require.NotContains(t, names, kmiplib.AttributeName("x-tag"))
}

// ModifyAttribute and DeleteAttribute refuse what a client cannot change,
// before any request.
func TestTranslator_ModifyDeleteAttributeRefusals(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	cases := []struct {
		attr   kmiplib.Attribute
		reason kmiplib.ResultReason
		msg    string
	}{
		{kmiplib.Attribute{AttributeName: kmiplib.AttributeNameState, AttributeValue: kmiplib.StateActive}, kmiplib.ResultReasonPermissionDenied, "attribute State is set by the server"},
		{kmiplib.Attribute{AttributeName: kmiplib.AttributeNameInitialDate, AttributeValue: time.Now()}, kmiplib.ResultReasonPermissionDenied, "attribute Initial Date is set by the server"},
		{dateAttr(kmiplib.AttributeNameCompromiseDate, time.Now()), kmiplib.ResultReasonPermissionDenied, "attribute Compromise Date is set by the server"},
		{dateAttr(kmiplib.AttributeNameCompromiseOccurrenceDate, time.Now()), kmiplib.ResultReasonPermissionDenied, "attribute Compromise Occurrence Date is set by the server"},
		{dateAttr(kmiplib.AttributeNameDestroyDate, time.Now()), kmiplib.ResultReasonPermissionDenied, "attribute Destroy Date is set by the server"},
		{kmiplib.Attribute{AttributeName: kmiplib.AttributeNameRevocationReason, AttributeValue: unspecified}, kmiplib.ResultReasonPermissionDenied, "attribute Revocation Reason is set by the server"},
		{kmiplib.Attribute{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-a"}}, kmiplib.ResultReasonInvalidField, "attribute Name cannot be"},
	}
	for _, tc := range cases {
		t.Run(string(tc.attr.AttributeName), func(t *testing.T) {
			_, err := op(t, ctx).modifyAttribute(ctx, "app-a", tc.attr)
			requireReason(t, err, tc.reason, tc.msg)
			_, err = op(t, ctx).deleteAttribute(ctx, "app-a", tc.attr.AttributeName, nil)
			requireReason(t, err, tc.reason, tc.msg)
			if classOf(tc.attr.AttributeName) == attrServerSet {
				err = op(t, ctx).addAttribute(ctx, "app-a", tc.attr)
				requireReason(t, err, tc.reason, tc.msg)
			}
		})
	}
	_, err := op(t, ctx).modifyAttribute(ctx, "app-a", kmiplib.Attribute{AttributeName: "x-empty"})
	requireReason(t, err, kmiplib.ResultReasonInvalidField, "attribute x-empty has no value")
	require.Empty(t, bao.all())
}

func TestTranslator_ModifyDeleteAttributeMissingObject(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	_, err := op(t, ctx).modifyAttribute(ctx, "app-missing", customAttr("x-tag", "blue"))
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, `object "app-missing" not found`)
	_, err = op(t, ctx).deleteAttribute(ctx, "app-missing", "x-tag", nil)
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, `object "app-missing" not found`)
}

// The Links ReKey wrote come first in the Link indexes and cannot be
// changed; a Link a client added follows them.
func TestTranslator_ModifyDeleteAttributeLinkIndexes(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)

	link := func(lt kmiplib.LinkType, uid string) kmiplib.Attribute {
		return kmiplib.Attribute{AttributeName: kmiplib.AttributeNameLink, AttributeValue: kmiplib.Link{LinkType: lt, LinkedObjectIdentifier: uid}}
	}
	index, err := op(t, ctx).addAttributeAt(ctx, "app-r.2", link(kmiplib.LinkTypeParentLink, "app-x"))
	require.NoError(t, err)
	require.Equal(t, int32(1), index)

	_, err = op(t, ctx).modifyAttribute(ctx, "app-r.2", link(kmiplib.LinkTypeChildLink, "app-y"))
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `Link of "app-r.2" is set by ReKey`)
	_, err = op(t, ctx).deleteAttribute(ctx, "app-r.2", kmiplib.AttributeNameLink, nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, `Link of "app-r.2" is set by ReKey`)

	got, err := op(t, ctx).modifyAttribute(ctx, "app-r.2", indexed(link(kmiplib.LinkTypeChildLink, "app-y"), 1))
	require.NoError(t, err)
	require.Equal(t, int32(1), *got.AttributeIndex)
	attrs, err := op(t, ctx).getAttributes(ctx, "app-r.2", []kmiplib.AttributeName{kmiplib.AttributeNameLink})
	require.NoError(t, err)
	require.Len(t, attrs, 2)
	require.True(t, sameValue(link(kmiplib.LinkTypeReplacedObjectLink, "app-r"), attrs[0]))
	require.True(t, sameValue(link(kmiplib.LinkTypeChildLink, "app-y"), attrs[1]))

	one, two := int32(1), int32(2)
	_, err = op(t, ctx).deleteAttribute(ctx, "app-r.2", kmiplib.AttributeNameLink, &two)
	requireReason(t, err, kmiplib.ResultReasonItemNotFound, "with Attribute Index 2")
	got, err = op(t, ctx).deleteAttribute(ctx, "app-r.2", kmiplib.AttributeNameLink, &one)
	require.NoError(t, err)
	require.True(t, sameValue(link(kmiplib.LinkTypeChildLink, "app-y"), got))
	requireAttr(t, attrsOf(t, ctx, "app-r.2"), kmiplib.AttributeNameLink, kmiplib.Link{LinkType: kmiplib.LinkTypeReplacedObjectLink, LinkedObjectIdentifier: "app-r"})
}

func attrsOf(t *testing.T, ctx context.Context, uid string) []kmiplib.Attribute {
	t.Helper()
	attrs, err := op(t, ctx).getAttributes(ctx, uid, nil)
	require.NoError(t, err)
	return attrs
}

// ModifyAttribute and DeleteAttribute refuse a replacement that a ReKey
// created and has not yet recorded, as AddAttribute does.
func TestTranslator_ModifyDeleteAttributeRefuseUninitializedSuccessor(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	m.write("app-r", claimOp(entryPending, "app-r.2", ""))
	m.createKey("app-r.2")

	start := len(bao.all())
	_, err := op(t, ctx).modifyAttribute(ctx, "app-r.2", dateAttr(kmiplib.AttributeNameActivationDate, time.Now()))
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "still being created")
	_, err = op(t, ctx).deleteAttribute(ctx, "app-r.2", "x-tag", nil)
	requireReason(t, err, kmiplib.ResultReasonPermissionDenied, "still being created")
	require.NotContains(t, since(bao, start), "POST transit/keys/app-r.2/metadata")
	require.Empty(t, m.record("app-r.2"))
}

// Concurrent ModifyAttributes of different attributes of one object all
// land: each re-reads the record after a lost check-and-set.
func TestTranslator_ModifyAttributeConcurrent(t *testing.T) {
	bao, m := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	const n = 8
	_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256, nil)
	require.NoError(t, err)
	for i := range n {
		require.NoError(t, op(t, ctx).addAttribute(ctx, "app-a", customAttr(fmt.Sprintf("x-%d", i), "before")))
	}

	calls := make([]*call, n)
	ctxs := make([]context.Context, n)
	for i := range n {
		ctxs[i], _ = newTestSession(t, bao, Config{})
		calls[i] = op(t, ctxs[i])
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = calls[i].modifyAttribute(ctxs[i], "app-a", customAttr(fmt.Sprintf("x-%d", i), "after"))
		})
	}
	wg.Wait()

	attrs := attrsOf(t, ctx, "app-a")
	for i := range n {
		require.NoError(t, errs[i], "x-%d", i)
		requireAttr(t, attrs, kmiplib.AttributeName(fmt.Sprintf("x-%d", i)), "after")
	}
	require.Len(t, m.record("app-a"), n)
}

// Resolve a Name again if ReKey moved it after Locate read its anchor.
func TestTranslator_LocateNameMovesDuringRead(t *testing.T) {
	bao, _ := transitBao(t)
	ctx, _ := newTestSession(t, bao, Config{})
	newRekeyKey(t, ctx)
	_, err := op(t, ctx).rekey(ctx, "app-r", nil, nil)
	require.NoError(t, err)
	original := bao.fallback
	moved := false
	bao.fallback = func(r fakeRequest) (int, any) {
		if !moved && r.method == http.MethodGet && r.path == "transit/keys/app-r.2/metadata" {
			moved = true
			_, moveErr := op(t, ctx).rekey(ctx, "app-r.2", nil, nil)
			require.NoError(t, moveErr)
		}
		return original(r)
	}
	ids, err := op(t, ctx).locate(ctx, []kmiplib.Attribute{{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: "app-r"}}})
	require.NoError(t, err)
	require.Equal(t, []string{"app-r.3"}, ids)
}
