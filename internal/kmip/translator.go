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

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"

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
	ClientToken   string            `json:"client_token"`
	TokenType     string            `json:"token_type"`
	LeaseDuration int               `json:"lease_duration"`
	Metadata      map[string]string `json:"metadata"`
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
		return kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "%s %s: response has no data", r.method, r.path)
	}
	if err := json.Unmarshal(r.Data, v); err != nil {
		return kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "%s %s: decoding response: %v", r.method, r.path, err)
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
	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  s.peerCerts,
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
		return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "no session for this KMIP connection")
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
		return "", kmipserver.Errorf(
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
		return kmipserver.Errorf(
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

func (c *call) create(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32) (string, error) {
	keyType, keySize, err := transitKeyType(alg, bitlen)
	if err != nil {
		return "", err
	}
	if name, err = c.keyName(ctx, name); err != nil {
		return "", err
	}

	rep, err := c.createKey(ctx, name, keyType, keySize)
	if err != nil {
		return "", err
	}

	// Transit answers a write to an existing key with that key and a
	// warning, but KMIP Create must make a new object.
	for _, warning := range rep.Warnings {
		if strings.Contains(warning, "already existed") {
			return "", kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "key %q already exists", name)
		}
	}
	return name, nil
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
// here, so it only travels wrapped.
func (c *call) register(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32, material []byte) (string, error) {
	keyType, _, err := transitKeyType(alg, bitlen)
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
		return "", rep.failure()
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
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonGeneralFailure,
			"transit returned no key material for version %s of %q", version, uid,
		)
	}
	return kmipObject(objType, alg, bitlen, material), nil
}

func errNotExportable(uid string) error {
	return kmipserver.Errorf(
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
				return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Name attribute is empty or invalid")
			}
			f.setOnce(&f.name, n.NameValue)
		case kmiplib.AttributeNameUniqueIdentifier:
			// UniqueIdentifier is the key name in transit.
			id, ok := attr.AttributeValue.(string)
			if !ok || id == "" {
				return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "UniqueIdentifier attribute is empty or invalid")
			}
			f.setOnce(&f.uid, id)
		case kmiplib.AttributeNameObjectType:
			ot, ok := attr.AttributeValue.(kmiplib.ObjectType)
			if !ok {
				return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "ObjectType attribute has invalid value")
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
				return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Locate filter %s has no value", attr.AttributeName)
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
// costs two reads at most however often it was rekeyed.
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
		uid, info, err := c.locateOne(ctx, f)
		if err != nil || info == nil || !f.matches(uid, info) {
			return nil, err
		}
		return []string{uid}, nil
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

// activate succeeds on an active key: transit keys are Active from creation
// and no transit state stands for Pre-Active.
func (c *call) activate(ctx context.Context, uid string) error {
	info, err := c.readKey(ctx, uid)
	if err != nil {
		return err
	}
	if info.SoftDeleted {
		return errSoftDeleted(uid)
	}
	return nil
}

// revoke soft-deletes the key, which KMIP reports as Deactivated. Transit
// registers soft-delete as a delete operation on keys/<uid>/soft-delete.
func (c *call) revoke(ctx context.Context, uid string) error {
	if err := checkName(uid); err != nil {
		return err
	}

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

// destroy deletes the key. Transit refuses unless the key's deletion_allowed
// is set, and KMIP does not set it.
func (c *call) destroy(ctx context.Context, uid string) error {
	if err := checkName(uid); err != nil {
		return err
	}

	// After a ReKey, the first generation of a Name holds the record that
	// resolves the Name to its current object. Deleting the key deletes that
	// record: Locate by Name then finds nothing, the next ReKey cannot
	// commit, and a Create may reuse the Name while a later generation still
	// holds it. Refuse while a later generation is current. The check reads
	// keys/<uid>; a role that may delete but not read skips it rather than
	// meet a new requirement.
	read, err := c.do(ctx, keyRead(uid))
	if err != nil {
		return err
	}
	if read.ok() {
		var info keyInfo
		if err := read.decode(&info); err != nil {
			return err
		}
		if _, err := c.loadMetadata(ctx, uid, &info, false); err != nil {
			return err
		}
		if current := info.single(entryCurrent); current != "" && current != uid {
			// Nothing clears current when the generation it names is
			// destroyed. Refuse only while that generation still exists:
			// with it gone the Name has no object left to lose, and refusing
			// would keep the anchor forever. A read of it that is denied
			// fails the Destroy rather than guess.
			live, err := c.lookupKey(ctx, current)
			if err != nil {
				return err
			}
			if live != nil {
				return kmipserver.Errorf(
					kmiplib.ResultReasonPermissionDenied,
					"wrong key lifecycle state: %q holds the Name that %q now carries; destroying it would lose that Name",
					uid, current,
				)
			}
		}
	}

	rep, err := c.do(ctx, request{method: http.MethodDelete, path: "keys/" + uid, capability: "delete"})
	if err != nil || rep.ok() {
		return err
	}

	msg := rep.message()
	switch {
	case rep.status == http.StatusForbidden:
	case strings.Contains(msg, "deletion is not allowed"):
		return kmipserver.Errorf(
			kmiplib.ResultReasonPermissionDenied,
			"transit will not delete %q until deletion_allowed is set with keys/%s/config", uid, uid,
		)
	case strings.Contains(msg, "not found"):
		return errNotFound(uid)
	}
	return rep.failure()
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
		return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "decoding plaintext from transit: %v", err)
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
