// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// metadataScope is the scope KMIP owns in a transit key's metadata record.
const metadataScope = "kmip"

// Entries of the kmip scope. Values are strings; attribute instances are
// base64 TTLV.
const (
	// entryAnchor holds the first generation's UID, on later generations.
	entryAnchor = "anchor"
	// entryGeneration holds the generation number, on later generations.
	entryGeneration = "generation"
	// entryCurrent holds the UID of the newest generation, on the anchor.
	entryCurrent = "current"
	// entrySwept holds the newest generation retention has soft-deleted,
	// on the anchor.
	entrySwept = "swept"
	// entryPending holds the successor a ReKey is creating, on the
	// predecessor, until the successor's record is written.
	entryPending = "pending_successor"

	entryAttrPrefix = "attr/"
	entryLinkPrefix = "link/"
)

// metadataOp is one change to the adapter's metadata record.
type metadataOp struct {
	Op       string `json:"op"`
	Scope    string `json:"scope"`
	Entry    string `json:"entry"`
	Value    string `json:"value,omitempty"`
	Expected string `json:"expected,omitempty"`
}

func addOp(entry, value string) metadataOp {
	return metadataOp{Op: "add", Scope: metadataScope, Entry: entry, Value: value}
}

func deleteOp(entry string) metadataOp {
	return metadataOp{Op: "delete", Scope: metadataScope, Entry: entry}
}

func claimOp(entry, value, expected string) metadataOp {
	return metadataOp{Op: "claim", Scope: metadataScope, Entry: entry, Value: value, Expected: expected}
}

func linkOp(entry, uid string) metadataOp {
	return metadataOp{Op: "link", Scope: metadataScope, Entry: entry, Value: uid}
}

// replaceOps sets entry to exactly values: a delete, then an add per value.
// Repeating them leaves the same entry, so an interrupted write is safe to
// write again.
func replaceOps(entry string, values ...string) []metadataOp {
	ops := []metadataOp{deleteOp(entry)}
	for _, v := range values {
		ops = append(ops, addOp(entry, v))
	}
	return ops
}

func linkEntry(lt kmiplib.LinkType) string {
	return entryLinkPrefix + ttlv.EnumStr(lt)
}

func attrEntry(name kmiplib.AttributeName) string {
	return entryAttrPrefix + string(name)
}

// metadataRecord holds scopes, entries and their values inside the adapter.
type metadataRecord map[string]map[string][]string

var errClaimHeld = errors.New("metadata claim is held")

func metadataRead(uid string) request {
	return request{method: http.MethodGet, path: "keys/" + uid + "/metadata", capability: "read"}
}

func decodeMetadata(data map[string]string) (metadataRecord, error) {
	record := metadataRecord{}
	for key, value := range data {
		entry, ok := strings.CutPrefix(key, metadataScope+"/")
		if !ok {
			continue
		}
		var values []string
		if err := json.Unmarshal([]byte(value), &values); err != nil || values == nil {
			return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "metadata key %q must hold a JSON string array", key)
		}
		if record[metadataScope] == nil {
			record[metadataScope] = map[string][]string{}
		}
		record[metadataScope][entry] = values
	}
	return record, nil
}

func (r metadataRecord) set(scope, entry string, values []string) {
	if len(values) > 0 {
		if r[scope] == nil {
			r[scope] = map[string][]string{}
		}
		r[scope][entry] = values
		return
	}
	delete(r[scope], entry)
	if len(r[scope]) == 0 {
		delete(r, scope)
	}
}

func (r metadataRecord) apply(op metadataOp) error {
	if op.Scope == "" || op.Entry == "" {
		return fmt.Errorf("%q needs a scope and an entry", op.Op)
	}
	values := r[op.Scope][op.Entry]
	switch op.Op {
	case "add":
		r.set(op.Scope, op.Entry, append(values, op.Value))
	case "delete":
		r.set(op.Scope, op.Entry, nil)
	case "claim":
		switch {
		case len(values) == 0,
			len(values) == 1 && values[0] == op.Value,
			len(values) == 1 && op.Expected != "" && values[0] == op.Expected:
			r.set(op.Scope, op.Entry, []string{op.Value})
		default:
			return fmt.Errorf("entry %q in scope %q is held by %q: %w", op.Entry, op.Scope, strings.Join(values, ","), errClaimHeld)
		}
	case "link":
		if !keyNameRegex.MatchString(op.Value) {
			return fmt.Errorf("link value %q is not a key name", op.Value)
		}
		r.set(op.Scope, op.Entry, []string{op.Value})
	default:
		return fmt.Errorf("unknown op %q: use add, delete, claim or link", op.Op)
	}
	return nil
}

func (c *call) loadMetadata(ctx context.Context, uid string, info *keyInfo, optional bool) (bool, error) {
	var rep *reply
	var err error
	if optional {
		rep, err = c.try(ctx, metadataRead(uid))
	} else {
		rep, err = c.do(ctx, metadataRead(uid))
	}
	if err != nil {
		return false, err
	}
	if optional && (rep.status == http.StatusForbidden || rep.status == http.StatusNotFound) {
		return false, nil
	}
	if !rep.ok() {
		return false, rep.failure()
	}
	var stored struct {
		Data map[string]string `json:"custom_metadata"`
	}
	if err := rep.decode(&stored); err != nil {
		return false, err
	}
	info.Metadata, err = decodeMetadata(stored.Data)
	if err != nil && optional {
		// The map is plain strings that any client with update may write, so
		// one malformed kmip/ value is possible. An optional read treats that
		// key like one it may not see: a Locate scan skips it rather than fail
		// for every key on the mount.
		c.s.t.logger.Warn("KMIP skipped a key whose metadata does not decode", "key", uid, "error", err)
		return false, nil
	}
	return err == nil, err
}

// writeMetadata applies ops with a version check. A concurrent writer makes
// the adapter read and apply again, preserving unrelated custom metadata.
// Bounds on writeMetadata's retries after a lost check-and-set.
const (
	metadataWriteAttempts = 8
	metadataBackoffBase   = 2 * time.Millisecond
	metadataBackoffMax    = 100 * time.Millisecond
)

func (c *call) writeMetadata(ctx context.Context, uid string, ops ...metadataOp) (*reply, error) {
	for attempt := range metadataWriteAttempts {
		rep, err := c.do(ctx, metadataRead(uid))
		if err != nil {
			return nil, err
		}
		if !rep.ok() {
			return rep, rep.failure()
		}
		var stored struct {
			Version uint64            `json:"version"`
			Data    map[string]string `json:"custom_metadata"`
		}
		if err := rep.decode(&stored); err != nil {
			return nil, err
		}
		record, err := decodeMetadata(stored.Data)
		if err != nil {
			return nil, err
		}
		for _, op := range ops {
			if err := record.apply(op); err != nil {
				return nil, err
			}
		}
		data := stored.Data
		if data == nil {
			data = map[string]string{}
		}
		for key := range data {
			if strings.HasPrefix(key, metadataScope+"/") {
				delete(data, key)
			}
		}
		for entry, values := range record[metadataScope] {
			encoded, err := json.Marshal(values)
			if err != nil {
				return nil, err
			}
			data[metadataScope+"/"+entry] = string(encoded)
		}
		rep, err = c.do(ctx, request{
			method: http.MethodPost, path: "keys/" + uid + "/metadata", capability: "update",
			body: map[string]any{"custom_metadata": data, "cas": stored.Version},
		})
		if err != nil {
			return nil, err
		}
		if rep.status == http.StatusBadRequest && strings.Contains(rep.message(), "check-and-set parameter did not match the current version") {
			if attempt < metadataWriteAttempts-1 {
				if err := metadataBackoff(ctx, attempt); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !rep.ok() {
			return rep, rep.failure()
		}
		// Keep the decoded record from this successful attempt for the
		// assigned attribute index and retention sweep.
		rep.metadata = record
		return rep, nil
	}
	return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "metadata record kept changing; retry")
}

// metadataBackoff waits before writeMetadata retries a write that lost a
// check-and-set race. Writers that collided and retry at once collide again,
// so each waits a random time up to a cap that doubles per attempt.
func metadataBackoff(ctx context.Context, attempt int) error {
	ceiling := min(metadataBackoffBase<<attempt, metadataBackoffMax)
	timer := time.NewTimer(time.Duration(rand.Int63n(int64(ceiling))) + 1)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// rekeyLinks are the Link types ReKey writes. GetAttributes reports them
// before any Link a client stored.
var rekeyLinks = []kmiplib.LinkType{kmiplib.LinkTypeReplacementObjectLink, kmiplib.LinkTypeReplacedObjectLink}

// attrClass says who sets an attribute.
type attrClass int

const (
	// attrStored attributes are kept verbatim and returned; they change
	// nothing.
	attrStored attrClass = iota
	// attrDerived attributes are read from the transit key.
	attrDerived
	// attrHonoured attributes are stored and change behaviour.
	attrHonoured
)

func classOf(name kmiplib.AttributeName) attrClass {
	switch name {
	case kmiplib.AttributeNameUniqueIdentifier,
		kmiplib.AttributeNameObjectType,
		kmiplib.AttributeNameCryptographicAlgorithm,
		kmiplib.AttributeNameCryptographicLength,
		kmiplib.AttributeNameState,
		kmiplib.AttributeNameInitialDate:
		return attrDerived
	case kmiplib.AttributeNameName:
		return attrHonoured
	}
	return attrStored
}

// singleInstance lists the stored attributes KMIP allows once per object.
// AddAttribute claims them, so a second value fails; every other stored
// attribute takes any number of instances.
var singleInstance = map[kmiplib.AttributeName]bool{
	kmiplib.AttributeNameCryptographicUsageMask:   true,
	kmiplib.AttributeNameLeaseTime:                true,
	kmiplib.AttributeNameContactInformation:       true,
	kmiplib.AttributeNameActivationDate:           true,
	kmiplib.AttributeNameProcessStartDate:         true,
	kmiplib.AttributeNameProtectStopDate:          true,
	kmiplib.AttributeNameDeactivationDate:         true,
	kmiplib.AttributeNameDestroyDate:              true,
	kmiplib.AttributeNameCompromiseOccurrenceDate: true,
	kmiplib.AttributeNameCompromiseDate:           true,
	kmiplib.AttributeNameArchiveDate:              true,
	kmiplib.AttributeNameLastChangeDate:           true,
	kmiplib.AttributeNameOriginalCreationDate:     true,
	kmiplib.AttributeNameRevocationReason:         true,
	kmiplib.AttributeNameFresh:                    true,
	kmiplib.AttributeNameDescription:              true,
	kmiplib.AttributeNameComment:                  true,
	kmiplib.AttributeNameSensitive:                true,
	kmiplib.AttributeNameExtractable:              true,
}

// encodeAttr returns an attribute instance as stored: base64 TTLV of the
// attribute without its index.
func encodeAttr(attr kmiplib.Attribute) string {
	attr.AttributeIndex = nil
	return base64.StdEncoding.EncodeToString(ttlv.MarshalTTLV(&attr))
}

func decodeAttr(uid, value string) (kmiplib.Attribute, error) {
	var attr kmiplib.Attribute
	raw, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		err = ttlv.UnmarshalTTLV(raw, &attr)
	}
	if err != nil {
		return attr, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "object %q has an undecodable stored attribute: %v", uid, err)
	}
	return attr, nil
}

// sameValue reports whether two instances of an attribute are equal.
func sameValue(a, b kmiplib.Attribute) bool {
	return a.AttributeName == b.AttributeName && encodeAttr(a) == encodeAttr(b)
}

// checkAttrValue rejects an attribute instance without a usable value.
func checkAttrValue(attr kmiplib.Attribute) error {
	if attr.AttributeValue == nil {
		return kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "attribute %s has no value", attr.AttributeName)
	}
	if attr.AttributeName == kmiplib.AttributeNameName {
		if n, ok := attr.AttributeValue.(kmiplib.Name); !ok || n.NameValue == "" {
			return kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Name attribute is empty or invalid")
		}
	}
	return nil
}

// objectAttrs returns every attribute of the object: derived from the
// transit key, then its Name, its links, and its stored attributes.
func objectAttrs(uid string, info *keyInfo) ([]kmiplib.Attribute, error) {
	alg, bitlen, objType, err := info.kmipAttrs()
	if err != nil {
		return nil, err
	}

	var attrs []kmiplib.Attribute
	if name, ok := info.kmipName(uid); ok {
		attrs = append(attrs, kmiplib.Attribute{
			AttributeName:  kmiplib.AttributeNameName,
			AttributeValue: kmiplib.Name{NameValue: name, NameType: kmiplib.NameTypeUninterpretedTextString},
		})
	}
	attrs = append(
		attrs,
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameUniqueIdentifier, AttributeValue: uid},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: objType},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: alg},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: bitlen},
		kmiplib.Attribute{AttributeName: kmiplib.AttributeNameState, AttributeValue: info.state()},
	)

	// InitialDate/ActivationDate come from the first key version, not the latest
	// rotation → fall back to MinDecryptionVersion if version 1 was archived.
	created, ok := info.createdAt(1)
	if !ok {
		created, ok = info.createdAt(info.MinDecryptionVersion)
	}
	if ok {
		attrs = append(attrs, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameInitialDate, AttributeValue: created})
		// State=Active is only consistent with an ActivationDate set → supply
		// it, unless the client stored its own.
		if len(info.entry(attrEntry(kmiplib.AttributeNameActivationDate))) == 0 {
			attrs = append(attrs, kmiplib.Attribute{AttributeName: kmiplib.AttributeNameActivationDate, AttributeValue: created})
		}
	}

	for _, lt := range rekeyLinks {
		if linked := info.single(linkEntry(lt)); linked != "" {
			attrs = append(attrs, kmiplib.Attribute{
				AttributeName:  kmiplib.AttributeNameLink,
				AttributeValue: kmiplib.Link{LinkType: lt, LinkedObjectIdentifier: linked},
			})
		}
	}

	stored, err := info.storedAttrs(uid)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, stored...)

	// The second and later instances of an attribute carry their index.
	seen := map[kmiplib.AttributeName]int32{}
	for i := range attrs {
		n := seen[attrs[i].AttributeName]
		seen[attrs[i].AttributeName] = n + 1
		if n > 0 {
			attrs[i].AttributeIndex = &n
		}
	}
	return attrs, nil
}

// storedAttrs decodes the object's stored attributes, ordered by name.
func (k *keyInfo) storedAttrs(uid string) ([]kmiplib.Attribute, error) {
	var entries []string
	for entry := range k.Metadata[metadataScope] {
		if strings.HasPrefix(entry, entryAttrPrefix) {
			entries = append(entries, entry)
		}
	}
	sort.Strings(entries)

	var attrs []kmiplib.Attribute
	for _, entry := range entries {
		for _, value := range k.entry(entry) {
			attr, err := decodeAttr(uid, value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		}
	}
	return attrs, nil
}

// storedEntries returns the object's stored attribute entries, to copy them
// onto a replacement.
func (k *keyInfo) storedEntries() map[string][]string {
	out := map[string][]string{}
	for entry, values := range k.Metadata[metadataScope] {
		if strings.HasPrefix(entry, entryAttrPrefix) {
			out[entry] = slices.Clone(values)
		}
	}
	return out
}

func (c *call) getAttributes(ctx context.Context, uid string, names []kmiplib.AttributeName) ([]kmiplib.Attribute, error) {
	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return nil, err
	}
	attrs, err := objectAttrs(uid, info)
	if err != nil || len(names) == 0 {
		return attrs, err
	}

	// Every instance of each requested attribute, in request order.
	var filtered []kmiplib.Attribute
	var done []kmiplib.AttributeName
	for _, want := range names {
		if slices.Contains(done, want) {
			continue
		}
		done = append(done, want)
		for _, attr := range attrs {
			if attr.AttributeName == want {
				filtered = append(filtered, attr)
			}
		}
	}
	return filtered, nil
}

func (c *call) getAttributeList(ctx context.Context, uid string) ([]kmiplib.AttributeName, error) {
	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return nil, err
	}
	attrs, err := objectAttrs(uid, info)
	if err != nil {
		return nil, err
	}

	var names []kmiplib.AttributeName
	for _, attr := range attrs {
		if !slices.Contains(names, attr.AttributeName) {
			names = append(names, attr.AttributeName)
		}
	}
	return names, nil
}

// addAttribute adds one attribute instance to the object. Derived
// attributes are refused before any request. Name is accepted only when it
// is the object's Name already: renaming would move the anchor.
func (c *call) addAttribute(ctx context.Context, uid string, attr kmiplib.Attribute) error {
	_, err := c.addAttributeAt(ctx, uid, attr)
	return err
}

// addAttributeAt adds attr to uid and returns the Attribute Index that
// GetAttributes gives the new instance.
func (c *call) addAttributeAt(ctx context.Context, uid string, attr kmiplib.Attribute) (int32, error) {
	if err := checkName(uid); err != nil {
		return 0, err
	}
	if err := checkAttrValue(attr); err != nil {
		return 0, err
	}
	if classOf(attr.AttributeName) == attrDerived {
		return 0, kmipserver.Errorf(
			kmiplib.ResultReasonPermissionDenied,
			"attribute %s is set by the server and cannot be added", attr.AttributeName,
		)
	}

	info, err := c.readKeyMetadata(ctx, uid)
	if err != nil {
		return 0, err
	}
	// ReKey creates its replacement and then writes the replacement's
	// record. In between, a write to the replacement would be replaced by
	// that record, or make a retry of the ReKey take the key for a foreign
	// one. Only a key with a generation suffix and no record can be in that
	// state, and only while its predecessor marks it as pending.
	if generationSuffix.MatchString(uid) && info.single(entryGeneration) == "" {
		pending, err := c.pendingSuccessor(ctx, uid)
		if err != nil {
			return 0, err
		}
		if pending {
			return 0, kmipserver.Errorf(
				kmiplib.ResultReasonPermissionDenied,
				"wrong key lifecycle state: %q is a ReKey replacement that is still being created", uid,
			)
		}
	}

	if attr.AttributeName == kmiplib.AttributeNameName {
		return 0, checkSameName(uid, info, attr.AttributeValue.(kmiplib.Name).NameValue)
	}

	entry := attrEntry(attr.AttributeName)
	op := addOp(entry, encodeAttr(attr))
	if singleInstance[attr.AttributeName] {
		op = claimOp(entry, op.Value, "")
	}
	rep, err := c.writeMetadata(ctx, uid, op)
	if errors.Is(err, errClaimHeld) {
		return 0, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"object %q already has a %s, which takes one value", uid, attr.AttributeName,
		)
	}
	if err != nil {
		return 0, err
	}

	// The write returns the record it stored, so this is the index this
	// write assigned, whatever other writers do after it.
	after := keyInfo{Metadata: rep.metadata}
	return after.lastIndex(attr.AttributeName), nil
}

// pendingSuccessor reports whether uid is a replacement that a ReKey created
// and has not yet recorded: its predecessor, A for A.2 and A.<n-1> for A.<n>,
// names it as pending_successor. A transit key that only looks like one,
// such as db.2024, is not. A predecessor that is missing or that the client
// may not read proves nothing, so it counts as not pending: a role is never
// refused for good over a key it cannot see.
func (c *call) pendingSuccessor(ctx context.Context, uid string) (bool, error) {
	i := strings.LastIndexByte(uid, '.')
	n, err := strconv.Atoi(uid[i+1:])
	if err != nil || n < 2 {
		return false, nil
	}
	pred := uid[:i]
	if n > 2 {
		pred += "." + strconv.Itoa(n-1)
	}
	if checkName(pred) != nil {
		return false, nil
	}
	// The read of uid just succeeded with this token, so a 403 here is a
	// denial: send once rather than log in again.
	rep, err := c.try(ctx, keyRead(pred))
	if err != nil {
		return false, err
	}
	info, err := candidate(rep)
	if err != nil || info == nil {
		return false, err
	}
	visible, err := c.loadMetadata(ctx, pred, info, true)
	return visible && info.single(entryPending) == uid, err
}

// lastIndex returns the Attribute Index that GetAttributes gives the newest
// instance of name, an attribute a client can add. It counts the way
// GetAttributes does: the Links ReKey wrote come first, then the stored
// instances in the order they were added. No derived attribute can be added,
// so none precedes them.
func (k *keyInfo) lastIndex(name kmiplib.AttributeName) int32 {
	n := len(k.entry(attrEntry(name)))
	if name == kmiplib.AttributeNameLink {
		for _, lt := range rekeyLinks {
			if k.single(linkEntry(lt)) != "" {
				n++
			}
		}
	}
	return int32(max(n-1, 0))
}

// checkSameName accepts name only when it is the object's Name.
func checkSameName(uid string, info *keyInfo, name string) error {
	current, ok := info.kmipName(uid)
	switch {
	case !ok:
		return kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"object %q was replaced by %q and has no Name; renaming is not supported", uid, info.replacement(),
		)
	case name != current:
		return kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"renaming is not supported: object %q has the Name %q", uid, current,
		)
	}
	return nil
}

// containsAttr reports whether attrs hold an instance equal to want.
func containsAttr(attrs []kmiplib.Attribute, want kmiplib.Attribute) bool {
	for _, attr := range attrs {
		if sameValue(attr, want) {
			return true
		}
	}
	return false
}

// templateEntries sorts the attributes of a ReKey template: stored
// attributes become entries for the replacement's record. The object's own
// Name, and a Cryptographic Algorithm, Cryptographic Length or Object Type
// equal to the predecessor's, are accepted and change nothing. Any other
// Name, and any other value of those three, is refused. Every other derived
// attribute is refused, even one equal to the predecessor's.
func templateEntries(uid string, info *keyInfo, template *kmiplib.TemplateAttribute) (map[string][]string, error) {
	out := map[string][]string{}
	if template == nil {
		return out, nil
	}
	//nolint:staticcheck // KMIP 1.2 clients may still reference templates by name
	if len(template.Name) > 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "templates referenced by name are not supported")
	}

	alg, bitlen, objType, err := info.kmipAttrs()
	if err != nil {
		return nil, err
	}
	for _, attr := range template.Attribute {
		if err := checkAttrValue(attr); err != nil {
			return nil, err
		}
		switch attr.AttributeName {
		case kmiplib.AttributeNameName:
			if err := checkSameName(uid, info, attr.AttributeValue.(kmiplib.Name).NameValue); err != nil {
				return nil, err
			}
			continue
		case kmiplib.AttributeNameCryptographicAlgorithm,
			kmiplib.AttributeNameCryptographicLength,
			kmiplib.AttributeNameObjectType:
			if !containsAttr([]kmiplib.Attribute{
				{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: alg},
				{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: bitlen},
				{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: objType},
			}, attr) {
				return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "ReKey cannot change the %s of %q", attr.AttributeName, uid)
			}
			continue
		}
		if classOf(attr.AttributeName) == attrDerived {
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonPermissionDenied,
				"attribute %s is set by the server and cannot be added", attr.AttributeName,
			)
		}
		entry := attrEntry(attr.AttributeName)
		if singleInstance[attr.AttributeName] {
			out[entry] = nil
		}
		out[entry] = append(out[entry], encodeAttr(attr))
	}
	return out, nil
}
