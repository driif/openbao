// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
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

	id, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256)
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
	require.ErrorContains(t, err, "login through auth/cert/login failed: no chain matching all constraints")
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
	require.ErrorContains(t, err, "GET transit/keys/k: status 500: storage unavailable")
	require.Len(t, bao.sent(http.MethodGet, "transit/keys/k"), 1)
	require.Equal(t, 1, bao.loginCount())
}

func TestTranslator_RejectsNamesOutsideTransitCharset(t *testing.T) {
	bao := newFakeBao(t)
	ctx, _ := newTestSession(t, bao, Config{})

	for _, name := range []string{"../sys/seal", "a/b", "key?x", "-lead", "trail-"} {
		_, err := op(t, ctx).create(ctx, name, kmiplib.CryptographicAlgorithmAES, 256)
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

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 256)
		require.ErrorContains(t, err, `key "app-a" already exists`)
	})

	t.Run("nameless", func(t *testing.T) {
		bao := newFakeBao(t)
		bao.fallback = keyRoute("hmac", map[string]any{"key_size": 64})
		ctx, _ := newTestSession(t, bao, Config{})

		id, err := op(t, ctx).create(ctx, "", kmiplib.CryptographicAlgorithmHMACSHA256, 512)
		require.NoError(t, err)
		require.Regexp(t, `^app-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, id)

		creates := bao.sent(http.MethodPost, "transit/keys/"+id)
		require.Len(t, creates, 1)
		require.Equal(t, map[string]any{"type": "hmac", "key_size": float64(64), "exportable": true}, creates[0].body)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		bao := newFakeBao(t)
		ctx, _ := newTestSession(t, bao, Config{})

		_, err := op(t, ctx).create(ctx, "app-a", kmiplib.CryptographicAlgorithmAES, 192)
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
	id, err := op(t, ctx).register(ctx, "app-imported", kmiplib.CryptographicAlgorithmAES, 256, material)
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
	require.ErrorContains(t, err, "GET transit/keys/rsa: status 500: storage unavailable")
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
	bao := newFakeBao(t)
	bao.route(http.MethodGet, "transit/keys/active", keyRoute("aes256-gcm96", nil))
	bao.route(http.MethodGet, "transit/keys/revoked", keyRoute("aes256-gcm96", map[string]any{"soft_deleted": true}))
	bao.route(http.MethodDelete, "transit/keys/active/soft-delete",
		keyRoute("aes256-gcm96", map[string]any{"soft_deleted": true}))
	// transit answers a soft-delete of a missing key with no content
	bao.route(http.MethodDelete, "transit/keys/gone/soft-delete", respond(http.StatusNoContent, nil))
	bao.route(http.MethodDelete, "transit/keys/active", respond(http.StatusNoContent, nil))
	bao.route(http.MethodDelete, "transit/keys/kept", respond(http.StatusBadRequest,
		withErrors("error deleting policy kept: deletion is not allowed for this key")))
	bao.route(http.MethodDelete, "transit/keys/gone", respond(http.StatusBadRequest,
		withErrors("error deleting policy gone: could not delete key; not found")))
	ctx, _ := newTestSession(t, bao, Config{})

	require.NoError(t, op(t, ctx).activate(ctx, "active"))
	require.ErrorContains(t, op(t, ctx).activate(ctx, "revoked"), "wrong key lifecycle state")

	require.NoError(t, op(t, ctx).revoke(ctx, "active"))
	require.Len(t, bao.sent(http.MethodDelete, "transit/keys/active/soft-delete"), 1)
	require.Empty(t, bao.sent(http.MethodDelete, "transit/keys/active"))
	require.ErrorContains(t, op(t, ctx).revoke(ctx, "gone"), `object "gone" not found`)

	require.NoError(t, op(t, ctx).destroy(ctx, "active"))
	require.Len(t, bao.sent(http.MethodDelete, "transit/keys/active"), 1)
	require.ErrorContains(t, op(t, ctx).destroy(ctx, "kept"), "until deletion_allowed is set with keys/kept/config")
	require.ErrorContains(t, op(t, ctx).destroy(ctx, "gone"), `object "gone" not found`)
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

	_, err = tr.connect(t.Context())
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
