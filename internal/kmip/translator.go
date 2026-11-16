// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	kmiplib "github.com/ovh/kmip-go"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/helper/forwarding"
	"github.com/openbao/openbao/v2/internal/helper/keywrap"
)

// keyNameRegex is transit's key name charset. Names become request path
// segments, so nothing else may reach a request.
var keyNameRegex = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")

// translator turns KMIP operations into requests against the OpenBao HTTP
// handler. One translator serves every connection on a listener.
type translator struct {
	handler      http.Handler
	namespace    string // the auth mount's namespace, sent as X-Vault-Namespace
	loginPath    string // relative to namespace
	defaultMount string
	logger       hclog.Logger
}

func newTranslator(handler http.Handler, cfg Config) (*translator, error) {
	namespace, authMount, err := splitAuthMount(cfg.AuthMount)
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	return &translator{
		handler:      handler,
		namespace:    namespace,
		loginPath:    authMount + "/login",
		defaultMount: strings.Trim(cfg.DefaultTransitMount, "/"),
		logger:       logger,
	}, nil
}

// splitAuthMount splits a namespace-qualified auth mount at its first "auth"
// segment: "tenant-a/auth/cert" is the mount auth/cert in namespace
// tenant-a. A namespace literally named "auth" therefore cannot be used.
func splitAuthMount(authMount string) (namespace, mount string, err error) {
	segments := strings.Split(strings.Trim(authMount, "/"), "/")
	i := slices.Index(segments, "auth")
	if i < 0 || i == len(segments)-1 {
		return "", "", fmt.Errorf("auth_mount %q must name a mount under auth/, such as auth/cert or ns1/auth/cert", authMount)
	}
	return strings.Join(segments[:i], "/"), strings.Join(segments[i:], "/"), nil
}

// request is one call to OpenBao. Transit calls carry a path relative to the
// transit mount; login and token calls one relative to the namespace.
type request struct {
	method     string
	path       string
	capability string // the ACL capability the call needs, named in denials
	query      url.Values
	body       map[string]any
}

// reply is a captured OpenBao HTTP response.
type reply struct {
	method     string
	path       string // namespace-qualified, as a policy would name it
	capability string
	status     int
	metadata   metadataRecord

	Data     json.RawMessage `json:"data"`
	Auth     *replyAuth      `json:"auth"`
	Warnings []string        `json:"warnings"`
	Errors   []string        `json:"errors"`
}

type replyAuth struct {
	ClientToken      string            `json:"client_token"`
	TokenType        string            `json:"token_type"`
	LeaseDuration    int               `json:"lease_duration"`
	Metadata         map[string]string `json:"metadata"`
	Accessor         string            `json:"accessor"`
	EntityID         string            `json:"entity_id"`
	Policies         []string          `json:"policies"`
	TokenPolicies    []string          `json:"token_policies"`
	IdentityPolicies []string          `json:"identity_policies"`
}

func (r *reply) ok() bool {
	return r.status >= 200 && r.status < 300
}

func (r *reply) message() string {
	if len(r.Errors) == 0 {
		return http.StatusText(r.status)
	}
	return strings.Join(r.Errors, "; ")
}

func (r *reply) decode(v any) error {
	if len(r.Data) == 0 {
		return operationErrorf(kmiplib.ResultReasonGeneralFailure, "%s %s: response has no data", r.method, r.path)
	}
	if err := json.Unmarshal(r.Data, v); err != nil {
		return operationErrorf(kmiplib.ResultReasonGeneralFailure, "%s %s: decoding response failed", r.method, r.path)
	}
	return nil
}

// roundTrip serves one synthetic request through the OpenBao handler. It
// carries the client's certificates and address, so cert login, audit and
// forwarding to the active node see the KMIP client as the caller.
func (t *translator) roundTrip(ctx context.Context, s *session, token string, r request) (*reply, error) {
	var payload io.Reader = http.NoBody
	if r.body != nil {
		buf, err := json.Marshal(r.body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(buf)
	}

	target := &url.URL{Path: "/v1/" + r.path, RawQuery: r.query.Encode()}
	req, err := http.NewRequestWithContext(ctx, r.method, target.String(), payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(consts.RequestHeaderName, "true")
	if token != "" {
		req.Header.Set(consts.AuthHeaderName, token)
	}
	if t.namespace != "" {
		req.Header.Set(consts.NamespaceHeaderName, t.namespace)
	}
	req.RemoteAddr = s.remoteAddr
	req.TLS = s.connectionState
	if req.TLS == nil {
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: s.peerCerts}
	}

	w := forwarding.NewRPCResponseWriter()
	t.handler.ServeHTTP(w, req)

	rep := &reply{
		method:     r.method,
		path:       t.qualify(r.path),
		capability: r.capability,
		status:     w.StatusCode(),
	}
	if raw := w.Body().Bytes(); len(raw) > 0 {
		if err := json.Unmarshal(raw, rep); err != nil {
			return nil, fmt.Errorf("%s %s: undecodable response with status %d: %w", rep.method, rep.path, rep.status, err)
		}
	}
	return rep, nil
}

func (t *translator) qualify(path string) string {
	if t.namespace == "" {
		return path
	}
	return t.namespace + "/" + path
}

// call is one KMIP operation's use of the session. OpenBao answers an
// expired or revoked token with the same 403 as an ACL denial, so after a
// 403 the call logs in again and retries, once per operation. A 403 means
// the request never ran, so even a write is safe to repeat. Transport errors
// and 5xx replies are never retried.
type call struct {
	s       *session
	retried bool
}

// begin starts a KMIP operation on the connection's session.
func begin(ctx context.Context) (*call, error) {
	s, ok := ctx.Value(sessionKey{}).(*session)
	if !ok {
		return nil, operationErrorf(kmiplib.ResultReasonGeneralFailure, "no session for this KMIP connection")
	}
	return &call{s: s}, nil
}

func (c *call) do(ctx context.Context, r request) (*reply, error) {
	rep, err := c.s.send(ctx, r)
	if err != nil || rep.status != http.StatusForbidden || c.retried {
		return rep, err
	}

	c.retried = true
	if err := c.s.relogin(ctx); err != nil {
		return nil, err
	}
	return c.s.send(ctx, r)
}

// try sends r once. Locate reads its candidates with it, since a 403 there
// only means the client may not see that key.
func (c *call) try(ctx context.Context, r request) (*reply, error) {
	return c.s.send(ctx, r)
}

// generationSuffix matches the UIDs ReKey gives later generations of a Name.
var generationSuffix = regexp.MustCompile(`\.[0-9]+$`)

// keyName returns the client's Name, or for a nameless object the role's
// kmip_key_prefix followed by a UUID.
func (c *call) keyName(ctx context.Context, name string) (string, error) {
	if generationSuffix.MatchString(name) {
		return "", operationErrorf(
			kmiplib.ResultReasonInvalidField,
			"invalid Name %q: a Name ending in '.' and digits is reserved for the replacements ReKey creates", name,
		)
	}
	if name == "" {
		prefix, err := c.s.prefix(ctx)
		if err != nil {
			return "", err
		}
		id, err := uuid.GenerateUUID()
		if err != nil {
			return "", err
		}
		name = prefix + id
	}
	return name, checkName(name)
}

func checkName(name string) error {
	if !keyNameRegex.MatchString(name) {
		return operationErrorf(
			kmiplib.ResultReasonInvalidField,
			"invalid key name %q: transit key names use letters, digits, '_', '-' and '.'", name,
		)
	}
	return nil
}

func keyRead(name string) request {
	return request{method: http.MethodGet, path: "keys/" + name, capability: "read"}
}

// readKey reads keys/<uid>. A missing key is Item Not Found.
func (c *call) readKey(ctx context.Context, uid string) (*keyInfo, error) {
	info, err := c.lookupKey(ctx, uid)
	if err == nil && info == nil {
		return nil, errNotFound(uid)
	}
	return info, err
}

// lookupKey reads keys/<uid>, returning nil for a missing key.
func (c *call) lookupKey(ctx context.Context, uid string) (*keyInfo, error) {
	if err := checkName(uid); err != nil {
		return nil, err
	}

	rep, err := c.do(ctx, keyRead(uid))
	if err != nil {
		return nil, err
	}
	switch {
	case rep.status == http.StatusNotFound:
		return nil, nil
	case !rep.ok():
		return nil, rep.failure()
	}

	var info keyInfo
	if err := rep.decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *call) readKeyMetadata(ctx context.Context, uid string) (*keyInfo, error) {
	info, err := c.lookupKeyMetadata(ctx, uid)
	if err == nil && info == nil {
		return nil, errNotFound(uid)
	}
	return info, err
}

func (c *call) lookupKeyMetadata(ctx context.Context, uid string) (*keyInfo, error) {
	info, err := c.lookupKey(ctx, uid)
	if err != nil || info == nil {
		return info, err
	}
	_, err = c.loadMetadata(ctx, uid, info, false)
	return info, err
}

// create makes a transit key and stores the stored attributes of template
// in its record, as storeTemplate describes.
func (c *call) create(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32, template *kmiplib.TemplateAttribute) (string, error) {
	keyType, keySize, err := transitKeyType(alg, bitlen)
	if err != nil {
		return "", err
	}
	entries, err := newObjectEntries("Create", name, alg, bitlen, keyType, keySize, template)
	if err != nil {
		return "", err
	}
	// A Name the server generates is a fresh UUID, so no other client can
	// hold the key; a client's Name may be shared, as storeTemplate explains.
	owned := name == ""
	if name, err = c.keyName(ctx, name); err != nil {
		return "", err
	}
	// Transit answers a create of an existing key with that key. A read
	// before the create refuses a key that exists already. A denied read
	// fails the Create before transit makes a key.
	if len(entries) > 0 {
		existing, err := c.lookupKey(ctx, name)
		if err != nil {
			return "", err
		}
		if existing != nil {
			return "", errKeyExists(name)
		}
	}

	rep, err := c.createKey(ctx, name, keyType, keySize)
	if err != nil {
		return "", err
	}

	// Transit answers a write to an existing key with that key and a
	// warning, but KMIP Create must make a new object.
	for _, warning := range rep.Warnings {
		if strings.Contains(warning, "already existed") {
			return "", errKeyExists(name)
		}
	}
	// Transit sends no such warning today. A soft-deleted key in the reply
	// still shows an existing one: a revoked or destroyed object, or a key
	// an earlier Create soft-deleted after its template write failed.
	if len(rep.Data) > 0 {
		var created keyInfo
		if err := rep.decode(&created); err != nil {
			return "", err
		}
		if created.SoftDeleted {
			return "", errKeyExists(name)
		}
	}
	if err := c.storeTemplate(ctx, "Create", name, entries, owned); err != nil {
		return "", err
	}
	return name, nil
}

func errKeyExists(name string) error {
	return operationErrorf(kmiplib.ResultReasonGeneralFailure, "key %q already exists", name)
}

// errRecordExists ends storeTemplate's write when the key already has KMIP
// entries: another client made or used the key after this operation found
// it missing.
var errRecordExists = errors.New("the key already has a KMIP record")

// storeTemplate writes the stored attributes of a new object's template to
// its record. Without any, it sends nothing, so a plain Create or Register
// needs no metadata grant.
//
// A Create or Register must not report success for an object that lacks
// its attributes, so a failed write fails the operation with General
// Failure naming the key. Transit has already made the key by then.
//
// owned says that no other client can hold the key: transit's import
// refuses an existing key, and a Name the server generates is a fresh
// UUID. Only then does storeTemplate soft-delete the key, best effort, so
// that it reports Deactivated and no cryptographic operation uses it. A
// client's Name proves nothing: another client can create the same Name
// between Create's read and its create, and transit hands both the one
// key. That key is left as it is. Either way a retry with the same Name
// fails because the key exists, and an operator restores, purges or keeps
// it. A record that already holds KMIP entries shows a key another KMIP
// client made: the operation fails and leaves it alone.
func (c *call) storeTemplate(ctx context.Context, op, uid string, entries map[string][]string, owned bool) error {
	if len(entries) == 0 {
		return nil
	}
	_, err := c.writeMetadataFunc(ctx, uid, func(record metadataRecord) error {
		if len(record[metadataScope]) > 0 {
			return errRecordExists
		}
		for entry, values := range entries {
			record.set(metadataScope, entry, slices.Clone(values))
		}
		return nil
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errRecordExists):
		return errKeyExists(uid)
	case !owned:
		return operationErrorf(
			kmiplib.ResultReasonGeneralFailure,
			"%s made the key %q but could not store its template attributes; the key was left in place because another client may hold the same Name: %v",
			op, uid, clientErrorText(err),
		)
	}

	if cleanupErr := c.softDelete(ctx, uid); cleanupErr != nil {
		return operationErrorf(
			kmiplib.ResultReasonGeneralFailure,
			"%s made the key %q but could not store its template attributes: %v; soft-deleting the key also failed, so it stays Active without them: %v",
			op, uid, clientErrorText(err), clientErrorText(cleanupErr),
		)
	}
	return operationErrorf(
		kmiplib.ResultReasonGeneralFailure,
		"%s made the key %q but could not store its template attributes, so the key was soft-deleted: %v",
		op, uid, clientErrorText(err),
	)
}

// softDelete soft-deletes the key, which KMIP reports as Deactivated.
// Transit registers soft-delete as a delete operation on
// keys/<uid>/soft-delete.
func (c *call) softDelete(ctx context.Context, uid string) error {
	rep, err := c.do(ctx, request{method: http.MethodDelete, path: "keys/" + uid + "/soft-delete", capability: "delete"})
	if err != nil {
		return err
	}
	switch {
	case rep.status == http.StatusNoContent:
		// Soft-deleting a key returns the key; a missing key returns nothing.
		return errNotFound(uid)
	case !rep.ok():
		return rep.failure()
	}
	return nil
}

// createKey posts keys/<name>. Get hands out key material, which transit
// only exports from keys created exportable.
func (c *call) createKey(ctx context.Context, name, keyType string, keySize int) (*reply, error) {
	body := map[string]any{"type": keyType, "exportable": true}
	if keySize > 0 {
		body["key_size"] = keySize
	}
	rep, err := c.do(ctx, request{method: http.MethodPost, path: "keys/" + name, capability: "update", body: body})
	if err != nil {
		return nil, err
	}
	if !rep.ok() {
		// The reply comes back with the error so a caller can tell a
		// refusal from a failure that may hide an applied create.
		return rep, rep.failure()
	}
	return rep, nil
}

// register imports key material: raw bytes for symmetric keys, PKCS#8 DER
// for private keys. The material is wrapped for transit's import endpoint
// here, so it only travels wrapped. The stored attributes of template go to
// the key's record, as storeTemplate describes.
func (c *call) register(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32, material []byte, template *kmiplib.TemplateAttribute) (string, error) {
	keyType, keySize, err := transitKeyType(alg, bitlen)
	if err != nil {
		return "", err
	}
	entries, err := newObjectEntries("Register", name, alg, bitlen, keyType, keySize, template)
	if err != nil {
		return "", err
	}
	if name, err = c.keyName(ctx, name); err != nil {
		return "", err
	}

	rep, err := c.do(ctx, request{method: http.MethodGet, path: "wrapping_key", capability: "read"})
	if err != nil {
		return "", err
	}
	if !rep.ok() {
		return "", rep.failure()
	}
	var wrapping struct {
		PublicKey string `json:"public_key"`
	}
	if err := rep.decode(&wrapping); err != nil {
		return "", err
	}
	wrappingKey, err := parseWrappingKey(wrapping.PublicKey)
	if err != nil {
		return "", err
	}
	wrapped, err := keywrap.Wrap(wrappingKey, material)
	if err != nil {
		return "", err
	}

	rep, err = c.do(ctx, request{
		method:     http.MethodPost,
		path:       "keys/" + name + "/import",
		capability: "update",
		body: map[string]any{
			"type":           keyType,
			"ciphertext":     base64.StdEncoding.EncodeToString(wrapped),
			"hash_function":  "SHA256",
			"exportable":     true,
			"allow_rotation": true,
		},
	})
	if err != nil {
		return "", err
	}
	if !rep.ok() {
		// Transit's import refuses an existing key, so a key it imports is
		// new, as storeTemplate requires.
		return "", rep.failure()
	}
	if err := c.storeTemplate(ctx, "Register", name, entries, true); err != nil {
		return "", err
	}
	return name, nil
}

func parseWrappingKey(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("transit returned a wrapping key that is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing transit wrapping key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("transit returned a wrapping key that is not RSA")
	}
	return rsaKey, nil
}

// get exports the latest version of the key. The key is read first because
// transit's export answers a soft-deleted key with a bare server error.
func (c *call) get(ctx context.Context, uid string) (kmiplib.Object, error) {
	info, err := c.readKey(ctx, uid)
	if err != nil {
		return nil, err
	}
	if info.SoftDeleted {
		return nil, errSoftDeleted(uid)
	}
	alg, bitlen, objType, err := info.kmipAttrs()
	if err != nil {
		return nil, err
	}
	if !info.Exportable {
		if objType == kmiplib.ObjectTypePrivateKey {
			// Transit publishes the public half of every asymmetric key, so a
			// key that cannot be exported still hands out its public key.
			return info.publicKey(alg, bitlen)
		}
		return nil, errNotExportable(uid)
	}

	exportType, format := info.exportSource(objType)
	version := strconv.Itoa(info.LatestVersion)
	rep, err := c.do(ctx, request{
		method:     http.MethodGet,
		path:       "export/" + exportType + "/" + uid + "/" + version,
		capability: "read",
		query:      url.Values{"format": {format}},
	})
	if err != nil {
		return nil, err
	}
	if !rep.ok() {
		if rep.status != http.StatusForbidden && strings.Contains(rep.message(), "not exportable") {
			return nil, errNotExportable(uid)
		}
		return nil, rep.failure()
	}

	var export struct {
		Keys map[string]string `json:"keys"`
	}
	if err := rep.decode(&export); err != nil {
		return nil, err
	}
	material, err := base64.StdEncoding.DecodeString(export.Keys[version])
	if err != nil || len(material) == 0 {
		return nil, operationErrorf(
			kmiplib.ResultReasonGeneralFailure,
			"transit returned no key material for version %s of %q", version, uid,
		)
	}
	return kmipObject(objType, alg, bitlen, material), nil
}

func errNotExportable(uid string) error {
	return operationErrorf(
		kmiplib.ResultReasonPermissionDenied,
		"key material of %q is not exportable: transit only exports keys created with exportable=true", uid,
	)
}

// locateFilter holds a Locate request's attributes. An exact Name or
// UniqueIdentifier selects one object by reading it; the attributes derived
// from the transit key are compared with it; every other attribute must
// equal one of the object's instances.
type locateFilter struct {
	name    string
	uid     string
	objType kmiplib.ObjectType
	alg     kmiplib.CryptographicAlgorithm
	bitlen  int32
	state   kmiplib.State
	attrs   []kmiplib.Attribute
	// empty is set when the filter contradicts itself, so nothing matches.
	empty bool
}

func parseLocateFilter(attrs []kmiplib.Attribute) (*locateFilter, error) {
	f := &locateFilter{}
	for _, attr := range attrs {
		switch attr.AttributeName {
		case kmiplib.AttributeNameName:
			n, ok := attr.AttributeValue.(kmiplib.Name)
			if !ok || n.NameValue == "" {
				return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Name attribute is empty or invalid")
			}
			f.setOnce(&f.name, n.NameValue)
		case kmiplib.AttributeNameUniqueIdentifier:
			// UniqueIdentifier is the key name in transit.
			id, ok := attr.AttributeValue.(string)
			if !ok || id == "" {
				return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "UniqueIdentifier attribute is empty or invalid")
			}
			f.setOnce(&f.uid, id)
		case kmiplib.AttributeNameObjectType:
			ot, ok := attr.AttributeValue.(kmiplib.ObjectType)
			if !ok {
				return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "ObjectType attribute has invalid value")
			}
			if f.objType != 0 && f.objType != ot {
				f.empty = true
			}
			f.objType = ot
		case kmiplib.AttributeNameCryptographicAlgorithm:
			f.alg, _ = attr.AttributeValue.(kmiplib.CryptographicAlgorithm)
		case kmiplib.AttributeNameCryptographicLength:
			f.bitlen, _ = attr.AttributeValue.(int32)
		case kmiplib.AttributeNameState:
			f.state, _ = attr.AttributeValue.(kmiplib.State)
		default:
			if attr.AttributeValue == nil {
				return nil, operationErrorf(kmiplib.ResultReasonInvalidField, "Locate filter %s has no value", attr.AttributeName)
			}
			f.attrs = append(f.attrs, attr)
		}
	}
	return f, nil
}

func (f *locateFilter) needsMetadata() bool {
	return f.name != "" || f.state != 0 || len(f.attrs) > 0
}

func (f *locateFilter) setOnce(field *string, value string) {
	if *field != "" && *field != value {
		f.empty = true
	}
	*field = value
}

// matches reports whether a key passes the filter. Keys with no KMIP
// representation never match, since no other operation could use them.
func (f *locateFilter) matches(uid string, info *keyInfo) bool {
	alg, bitlen, objType, err := info.kmipAttrs()
	switch {
	case err != nil:
		return false
	case f.state != 0 && info.state() != f.state:
		return false
	case f.objType != 0 && objType != f.objType:
		return false
	case f.alg != 0 && alg != f.alg:
		return false
	case f.bitlen != 0 && bitlen != f.bitlen:
		return false
	}
	if f.name != "" {
		if name, ok := info.kmipName(uid); !ok || name != f.name {
			return false
		}
	}
	if len(f.attrs) == 0 {
		return true
	}

	attrs, err := objectAttrs(uid, info)
	if err != nil {
		return false
	}
	for _, want := range f.attrs {
		if !containsAttr(attrs, want) {
			return false
		}
	}
	return true
}

// candidate decodes a Locate read. A key the client may not read, or that
// is gone, is nil; any other failure fails the Locate.
func candidate(rep *reply) (*keyInfo, error) {
	switch {
	case rep.status == http.StatusForbidden, rep.status == http.StatusNotFound:
		return nil, nil
	case !rep.ok():
		return nil, rep.failure()
	}

	var info keyInfo
	if err := rep.decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// locateOne reads the object an exact UID or Name selects. A Name is the
// UID of its anchor, whose record names the current generation, so a Name
// costs two reads at most when no ReKey moves it during the lookup.
func (c *call) locateOne(ctx context.Context, f *locateFilter) (string, *keyInfo, error) {
	uid := f.uid
	if uid == "" {
		uid = f.name
	}
	if checkName(uid) != nil {
		return "", nil, nil
	}
	rep, err := c.do(ctx, keyRead(uid))
	if err != nil {
		return "", nil, err
	}
	info, err := candidate(rep)
	if err != nil || info == nil {
		return uid, info, err
	}
	if f.needsMetadata() {
		visible, err := c.loadMetadata(ctx, uid, info, true)
		if err != nil || !visible {
			return uid, nil, err
		}
	}
	if f.uid != "" {
		return uid, info, nil
	}

	current := info.single(entryCurrent)
	if current == "" || current == uid || checkName(current) != nil {
		return uid, info, nil
	}
	// The first read succeeded with this token, so a 403 here is a denial,
	// not an expired token: send once, as Locate's other reads do, rather
	// than revoke the token and log in again.
	rep, err = c.try(ctx, keyRead(current))
	if err != nil {
		return "", nil, err
	}
	info, err = candidate(rep)
	if err == nil && info != nil {
		visible, readErr := c.loadMetadata(ctx, current, info, true)
		if readErr != nil || !visible {
			return current, nil, readErr
		}
	}
	return current, info, err
}

// locate returns every key matching attrs that the client may read.
func (c *call) locate(ctx context.Context, attrs []kmiplib.Attribute) ([]string, error) {
	f, err := parseLocateFilter(attrs)
	if err != nil || f.empty {
		return nil, err
	}

	// An exact Name or UID reads and does not list, so a policy without
	// list on keys still locates the keys it names.
	if f.uid != "" || f.name != "" {
		moved := make(map[string]bool)
		for {
			uid, info, err := c.locateOne(ctx, f)
			if err != nil || info == nil {
				return nil, err
			}
			// ReKey commits the anchor before removing the predecessor's
			// Name. If that happened between these reads, resolve the new
			// current generation instead of reporting that the Name is gone.
			// A repeated UID means the anchor did not advance; do not loop on
			// an inconsistent record or a cycle in manually edited metadata.
			if f.uid == "" && info.replacement() != "" && !moved[uid] {
				if name, ok := info.kmipName(uid); !ok || name != f.name {
					moved[uid] = true
					continue
				}
			}
			if !f.matches(uid, info) {
				return nil, nil
			}
			return []string{uid}, nil
		}
	}

	rep, err := c.do(ctx, request{method: "LIST", path: "keys", capability: "list"})
	if err != nil {
		return nil, err
	}
	switch {
	case rep.status == http.StatusNotFound:
		// transit lists no keys as a 404
		return nil, nil
	case !rep.ok():
		return nil, rep.failure()
	}
	var list struct {
		Keys []string `json:"keys"`
	}
	if err := rep.decode(&list); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(list.Keys))
	for _, name := range list.Keys {
		if checkName(name) != nil {
			continue
		}
		rep, err := c.try(ctx, keyRead(name))
		if err != nil {
			return nil, err
		}
		info, err := candidate(rep)
		if err != nil {
			return nil, err
		}
		if info != nil && f.needsMetadata() {
			visible, err := c.loadMetadata(ctx, name, info, true)
			if err != nil {
				return nil, err
			}
			if !visible {
				continue
			}
		}
		if info != nil && f.matches(name, info) {
			ids = append(ids, name)
		}
	}
	return ids, nil
}

// activate makes a Pre-Active object Active by storing now as its
// Activation Date. An Active object succeeds with no write; any other State
// is refused. The metadata read is required: the marks and the dates that
// decide the State are only there. A stored date that does not decode fails
// Activate, on the first read and on each write attempt.
func (c *call) activate(ctx context.Context, uid string) error {
	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return err
	}
	check := func(info *keyInfo) error {
		state, err := info.checkedState()
		if err != nil {
			return err
		}
		switch state {
		case kmiplib.StatePreActive:
			return nil
		case kmiplib.StateActive:
			return errNoChange
		default:
			return errWrongState(uid, state)
		}
	}
	if err := check(info); err != nil {
		if errors.Is(err, errNoChange) {
			return nil
		}
		return err
	}

	now := time.Now()
	_, err = c.writeMetadataFunc(ctx, uid, func(record metadataRecord) error {
		if err := check(info.withRecord(record)); err != nil {
			return err
		}
		setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameActivationDate, AttributeValue: now})
		return nil
	})
	return err
}

// isCompromise reports whether reason places the object in the Compromised
// state.
func isCompromise(reason kmiplib.RevocationReason) bool {
	return reason.RevocationReasonCode == kmiplib.RevocationReasonCodeKeyCompromise ||
		reason.RevocationReasonCode == kmiplib.RevocationReasonCodeCACompromise
}

// revoke records the revocation in the object's record, then soft-deletes
// the key. Key Compromise and CA Compromise set the compromise mark, the
// Compromise Date and the Compromise Occurrence Date: occurrence, or else
// the Initial Date. A repeated compromise Revoke keeps the first dates. Any
// other reason sets the Deactivation Date to now, unless one at or before
// now is stored. Both store the Revocation Reason.
//
// KMIP 1.4 has no transition out of Destroyed, and none from Pre-Active or
// Compromised to Deactivated, so Revoke refuses a Destroyed object, and a
// Revoke with any other reason refuses a Pre-Active or Compromised one.
//
// The record goes first. If the soft-delete then fails, the object already
// reports Compromised, or Deactivated by its date, never a State less
// restrictive than before, and a retry of the Revoke finishes it.
func (c *call) revoke(ctx context.Context, uid string, reason kmiplib.RevocationReason, occurrence *time.Time) error {
	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return err
	}
	compromise := isCompromise(reason)
	check := func(info *keyInfo) error {
		switch state := info.state(); state {
		case kmiplib.StateDestroyed, kmiplib.StateDestroyedCompromised:
			return errWrongState(uid, state)
		case kmiplib.StatePreActive, kmiplib.StateCompromised:
			if !compromise {
				return errWrongState(uid, state)
			}
		}
		return nil
	}
	if err := check(info); err != nil {
		return err
	}

	now := time.Now()
	_, err = c.writeMetadataFunc(ctx, uid, func(record metadataRecord) error {
		current := info.withRecord(record)
		if err := check(current); err != nil {
			return err
		}
		switch {
		case compromise && current.single(entryCompromised) == "":
			record.set(metadataScope, entryCompromised, []string{markSet})
			setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCompromiseDate, AttributeValue: now})
			// An HMAC key lists no versions and so has no Initial Date:
			// without a date in the request, none is stored.
			occurred, ok := current.initialDate()
			if occurrence != nil {
				occurred, ok = *occurrence, true
			}
			if ok {
				setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCompromiseOccurrenceDate, AttributeValue: occurred})
			}
		case !compromise:
			// A stored Deactivation Date that does not decode is replaced.
			if at, ok, err := current.storedDate(kmiplib.AttributeNameDeactivationDate); err != nil || !ok || at.After(now) {
				setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameDeactivationDate, AttributeValue: now})
			}
		}
		setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameRevocationReason, AttributeValue: reason})
		return nil
	})
	if err != nil || info.SoftDeleted {
		return err
	}
	return c.softDelete(ctx, uid)
}

// destroy places a Pre-Active, Deactivated or Compromised object in the
// Destroyed state, or Destroyed Compromised for a compromised one. It never
// deletes the key: purging it is an operator action outside KMIP. It
// soft-deletes the key unless it is soft-deleted already, then sets the
// destroy mark and the Destroy Date. Destroy of an Active object is refused;
// of a Destroyed one, it succeeds with no write.
//
// The soft-delete goes first, so Get never returns material of an object
// that reports Destroyed. If the record write then fails, the object reports
// Deactivated, which a retry of the Destroy accepts.
func (c *call) destroy(ctx context.Context, uid string) error {
	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return err
	}
	switch state := info.state(); state {
	case kmiplib.StateDestroyed, kmiplib.StateDestroyedCompromised:
		return nil
	case kmiplib.StateActive:
		return errWrongState(uid, state)
	}

	if !info.SoftDeleted {
		if err := c.softDelete(ctx, uid); err != nil {
			return err
		}
		info.SoftDeleted = true
	}

	now := time.Now()
	_, err = c.writeMetadataFunc(ctx, uid, func(record metadataRecord) error {
		if info.withRecord(record).single(entryDestroyed) != "" {
			// A concurrent Destroy got there first; keep its Destroy Date.
			return errNoChange
		}
		record.set(metadataScope, entryDestroyed, []string{markSet})
		setAttr(record, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameDestroyDate, AttributeValue: now})
		return nil
	})
	return err
}

// cryptoOp posts body to <op>/<uid> and decodes the reply's data into out.
func (c *call) cryptoOp(ctx context.Context, op, uid string, body map[string]any, out any) error {
	if err := checkName(uid); err != nil {
		return err
	}

	rep, err := c.do(ctx, request{method: http.MethodPost, path: op + "/" + uid, capability: "update", body: body})
	if err != nil {
		return err
	}
	if !rep.ok() {
		return rep.failure()
	}
	return rep.decode(out)
}

func (c *call) encrypt(ctx context.Context, uid string, plaintext []byte) ([]byte, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	err := c.cryptoOp(ctx, "encrypt", uid, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, &out)
	if err != nil {
		return nil, err
	}
	return []byte(out.Ciphertext), nil
}

func (c *call) decrypt(ctx context.Context, uid string, ciphertext []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	err := c.cryptoOp(ctx, "decrypt", uid, map[string]any{
		"ciphertext": string(ciphertext),
	}, &out)
	if err != nil {
		return nil, err
	}

	// transit returns base64-encoded plaintext → decode back to raw bytes.
	plaintext, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, operationErrorf(kmiplib.ResultReasonGeneralFailure, "decoding plaintext from transit failed")
	}
	return plaintext, nil
}

// sign signs the SHA-256 digest of data, which transit computes, with the
// key's default signature algorithm.
func (c *call) sign(ctx context.Context, uid string, data []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature"`
	}
	err := c.cryptoOp(ctx, "sign", uid, map[string]any{
		"input":                base64.StdEncoding.EncodeToString(data),
		"hash_algorithm":       "sha2-256",
		"marshaling_algorithm": "asn1",
	}, &out)
	if err != nil {
		return nil, err
	}
	return []byte(out.Signature), nil
}

// verify must match sign → verify against the same SHA-256 digest.
func (c *call) verify(ctx context.Context, uid string, data, signature []byte) (bool, error) {
	var out struct {
		Valid bool `json:"valid"`
	}
	err := c.cryptoOp(ctx, "verify", uid, map[string]any{
		"input":                base64.StdEncoding.EncodeToString(data),
		"signature":            string(signature),
		"hash_algorithm":       "sha2-256",
		"marshaling_algorithm": "asn1",
	}, &out)
	if err != nil {
		return false, err
	}
	return out.Valid, nil
}
