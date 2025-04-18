// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/testhelpers/corehelpers"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/mitchellh/copystructure"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestAudit_ReadOnlyViewDuringMount(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		err := config.SaltView.Put(ctx, &logical.StorageEntry{
			Key:   "bar",
			Value: []byte("baz"),
		})
		if err == nil || !strings.Contains(err.Error(), logical.ErrSetupReadOnly.Error()) {
			t.Fatal("expected a read-only error")
		}
		factory := corehelpers.NoopAuditFactory(nil)
		return factory(ctx, config)
	}

	me := &MountEntry{
		Table: auditTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.enableAudit(namespace.RootContext(nil), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestCore_EnableAudit(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)

	me := &MountEntry{
		Table: auditTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err := c.enableAudit(namespace.RootContext(nil), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !c.auditBroker.IsRegistered("foo/") {
		t.Fatal("missing audit backend")
	}

	conf := &CoreConfig{
		Physical:      c.physical,
		AuditBackends: make(map[string]audit.Factory),
	}
	conf.AuditBackends["noop"] = corehelpers.NoopAuditFactory(nil)
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching audit tables
	if !reflect.DeepEqual(c.audit, c2.audit) {
		t.Fatalf("mismatch: %v %v", c.audit, c2.audit)
	}

	// Check for registration
	if !c2.auditBroker.IsRegistered("foo/") {
		t.Fatal("missing audit backend")
	}
}

func TestCore_EnableAudit_MixedFailures(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)
	c.auditBackends["fail"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		return nil, errors.New("failing enabling")
	}

	c.audit = &MountTable{
		Type: auditTableType,
		Entries: []*MountEntry{
			{
				Table: auditTableType,
				Path:  "noop/",
				Type:  "noop",
				UUID:  "abcd",
			},
			{
				Table: auditTableType,
				Path:  "noop2/",
				Type:  "noop",
				UUID:  "bcde",
			},
		},
	}

	// Both should set up successfully
	err := c.setupAudits(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// We expect this to work because the other entry is still valid
	c.audit.Entries[0].Type = "fail"
	err = c.setupAudits(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// No audit backend set up successfully, so expect error
	c.audit.Entries[1].Type = "fail"
	err = c.setupAudits(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

// Test that the local table actually gets populated as expected with local
// entries, and that upon reading the entries from both are recombined
// correctly
func TestCore_EnableAudit_Local(t *testing.T) {
	c, _, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)
	c.auditBackends["fail"] = func(ctx context.Context, config *audit.BackendConfig) (audit.Backend, error) {
		return nil, errors.New("failing enabling")
	}

	c.audit = &MountTable{
		Type: auditTableType,
		Entries: []*MountEntry{
			{
				Table:       auditTableType,
				Path:        "noop/",
				Type:        "noop",
				UUID:        "abcd",
				Accessor:    "noop-abcd",
				NamespaceID: namespace.RootNamespaceID,
				namespace:   namespace.RootNamespace,
			},
			{
				Table:       auditTableType,
				Path:        "noop2/",
				Type:        "noop",
				UUID:        "bcde",
				Accessor:    "noop-bcde",
				NamespaceID: namespace.RootNamespaceID,
				namespace:   namespace.RootNamespace,
			},
		},
	}

	// Both should set up successfully
	err := c.setupAudits(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rawLocal, err := c.barrier.Get(context.Background(), coreLocalAuditConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if rawLocal == nil {
		t.Fatal("expected non-nil local audit")
	}
	localAuditTable := &MountTable{}
	if err := jsonutil.DecodeJSON(rawLocal.Value, localAuditTable); err != nil {
		t.Fatal(err)
	}
	if len(localAuditTable.Entries) > 0 {
		t.Fatalf("expected no entries in local audit table, got %#v", localAuditTable)
	}

	c.audit.Entries[1].Local = true
	if err := c.persistAudit(context.Background(), c.audit, false); err != nil {
		t.Fatal(err)
	}

	rawLocal, err = c.barrier.Get(context.Background(), coreLocalAuditConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if rawLocal == nil {
		t.Fatal("expected non-nil local audit")
	}
	localAuditTable = &MountTable{}
	if err := jsonutil.DecodeJSON(rawLocal.Value, localAuditTable); err != nil {
		t.Fatal(err)
	}
	if len(localAuditTable.Entries) != 1 {
		t.Fatalf("expected one entry in local audit table, got %#v", localAuditTable)
	}

	oldAudit := c.audit
	if err := c.loadAudits(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(oldAudit, c.audit) {
		t.Fatalf("expected\n%#v\ngot\n%#v\n", oldAudit, c.audit)
	}

	if len(c.audit.Entries) != 2 {
		t.Fatalf("expected two audit entries, got %#v", localAuditTable)
	}
}

func TestCore_DisableAudit(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	c.auditBackends["noop"] = corehelpers.NoopAuditFactory(nil)

	existed, err := c.disableAudit(namespace.RootContext(nil), "foo", true)
	if existed && err != nil {
		t.Fatalf("existed: %v; err: %v", existed, err)
	}

	me := &MountEntry{
		Table: auditTableType,
		Path:  "foo",
		Type:  "noop",
	}
	err = c.enableAudit(namespace.RootContext(nil), me, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	existed, err = c.disableAudit(namespace.RootContext(nil), "foo", true)
	if !existed || err != nil {
		t.Fatalf("existed: %v; err: %v", existed, err)
	}

	// Check for registration
	if c.auditBroker.IsRegistered("foo") {
		t.Fatal("audit backend present")
	}

	conf := &CoreConfig{
		Physical: c.physical,
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if !reflect.DeepEqual(c.audit, c2.audit) {
		t.Fatalf("mismatch:\n%#v\n%#v", c.audit, c2.audit)
	}
}

func TestCore_DefaultAuditTable(t *testing.T) {
	c, keys, _ := TestCoreUnsealed(t)
	verifyDefaultAuditTable(t, c.audit)

	// Verify we have an audit broker
	if c.auditBroker == nil {
		t.Fatal("missing audit broker")
	}

	// Start a second core with same physical
	conf := &CoreConfig{
		Physical: c.physical,
	}
	c2, err := NewCore(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Shutdown()
	for i, key := range keys {
		unseal, err := TestCoreUnseal(c2, key)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if i+1 == len(keys) && !unseal {
			t.Fatal("should be unsealed")
		}
	}

	// Verify matching mount tables
	if !reflect.DeepEqual(c.audit, c2.audit) {
		t.Fatalf("mismatch: %v %v", c.audit, c2.audit)
	}
}

func TestDefaultAuditTable(t *testing.T) {
	table := defaultAuditTable()
	verifyDefaultAuditTable(t, table)
}

func verifyDefaultAuditTable(t *testing.T, table *MountTable) {
	if len(table.Entries) != 0 {
		t.Fatalf("bad: %v", table.Entries)
	}
	if table.Type != auditTableType {
		t.Fatalf("bad: %v", *table)
	}
}

func TestAuditBroker_LogRequest(t *testing.T) {
	l := logging.NewVaultLogger(log.Trace)
	b := NewAuditBroker(l)
	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
	}

	// Copy so we can verify nothing changed
	authCopyRaw, err := copystructure.Copy(auth)
	if err != nil {
		t.Fatal(err)
	}
	authCopy := authCopyRaw.(*logical.Auth)

	reqCopyRaw, err := copystructure.Copy(req)
	if err != nil {
		t.Fatal(err)
	}
	reqCopy := reqCopyRaw.(*logical.Request)

	// Create an identifier for the request to verify against
	req.ID, err = uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("failed to generate identifier for the request: path%s err: %v", req.Path, err)
	}
	reqCopy.ID = req.ID

	reqErrs := errors.New("errs")

	headersConf := &AuditedHeadersConfig{
		Headers: make(map[string]*auditedHeaderSettings),
	}

	logInput := &logical.LogInput{
		Auth:     authCopy,
		Request:  reqCopy,
		OuterErr: reqErrs,
	}
	ctx := namespace.RootContext(context.Background())
	err = b.LogRequest(ctx, logInput, headersConf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		if !reflect.DeepEqual(a.ReqAuth[0], auth) {
			t.Fatalf("Bad: %#v", a.ReqAuth[0])
		}
		if !reflect.DeepEqual(a.Req[0], req) {
			t.Fatalf("Bad: %#v\n wanted %#v", a.Req[0], req)
		}
		if !reflect.DeepEqual(a.ReqErrs[0], reqErrs) {
			t.Fatalf("Bad: %#v", a.ReqErrs[0])
		}
	}

	// Should still work with one failing backend
	a1.ReqErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:    auth,
		Request: req,
	}
	if err := b.LogRequest(ctx, logInput, headersConf); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should FAIL work with both failing backends
	a2.ReqErr = errors.New("failed")
	if err := b.LogRequest(ctx, logInput, headersConf); !errwrap.Contains(err, "no audit backend succeeded in logging the request") {
		t.Fatalf("err: %v", err)
	}
}

func TestAuditBroker_LogResponse(t *testing.T) {
	l := logging.NewVaultLogger(log.Trace)
	b := NewAuditBroker(l)
	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		NumUses:     10,
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
	}
	resp := &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: 1 * time.Hour,
			},
		},
		Data: map[string]interface{}{
			"user":     "root",
			"password": "password",
		},
	}
	respErr := errors.New("permission denied")

	// Copy so we can verify nothing changed
	authCopyRaw, err := copystructure.Copy(auth)
	if err != nil {
		t.Fatal(err)
	}
	authCopy := authCopyRaw.(*logical.Auth)

	reqCopyRaw, err := copystructure.Copy(req)
	if err != nil {
		t.Fatal(err)
	}
	reqCopy := reqCopyRaw.(*logical.Request)

	respCopyRaw, err := copystructure.Copy(resp)
	if err != nil {
		t.Fatal(err)
	}
	respCopy := respCopyRaw.(*logical.Response)

	headersConf := &AuditedHeadersConfig{
		Headers: make(map[string]*auditedHeaderSettings),
	}

	logInput := &logical.LogInput{
		Auth:     authCopy,
		Request:  reqCopy,
		Response: respCopy,
		OuterErr: respErr,
	}
	ctx := namespace.RootContext(context.Background())
	err = b.LogResponse(ctx, logInput, headersConf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		if !reflect.DeepEqual(a.RespAuth[0], auth) {
			t.Fatalf("Bad: %#v", a.ReqAuth[0])
		}
		if !reflect.DeepEqual(a.RespReq[0], req) {
			t.Fatalf("Bad: %#v", a.Req[0])
		}
		if !reflect.DeepEqual(a.Resp[0], resp) {
			t.Fatalf("Bad: %#v", a.Resp[0])
		}
		if !reflect.DeepEqual(a.RespErrs[0], respErr) {
			t.Fatalf("Expected\n%v\nGot\n%#v", respErr, a.RespErrs[0])
		}
	}

	// Should still work with one failing backend
	a1.RespErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:     auth,
		Request:  req,
		Response: resp,
		OuterErr: respErr,
	}
	err = b.LogResponse(ctx, logInput, headersConf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should FAIL work with both failing backends
	a2.RespErr = errors.New("failed")
	err = b.LogResponse(ctx, logInput, headersConf)
	if !strings.Contains(err.Error(), "no audit backend succeeded in logging the response") {
		t.Fatalf("err: %v", err)
	}
}

func TestAuditBroker_AuditHeaders(t *testing.T) {
	logger := logging.NewVaultLogger(log.Trace)
	b := NewAuditBroker(logger)
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "headers/")
	a1 := corehelpers.TestNoopAudit(t, nil)
	a2 := corehelpers.TestNoopAudit(t, nil)
	b.Register("foo", a1, nil, false)
	b.Register("bar", a2, nil, false)

	auth := &logical.Auth{
		ClientToken: "foo",
		Policies:    []string{"dev", "ops"},
		Metadata: map[string]string{
			"user":   "armon",
			"source": "github",
		},
	}
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sys/mounts",
		Headers: map[string][]string{
			"X-Test-Header":  {"foo"},
			"X-Vault-Header": {"bar"},
			"Content-Type":   {"baz"},
		},
	}
	respErr := errors.New("permission denied")

	// Copy so we can verify nothing changed
	reqCopyRaw, err := copystructure.Copy(req)
	if err != nil {
		t.Fatal(err)
	}
	reqCopy := reqCopyRaw.(*logical.Request)

	headersConf := &AuditedHeadersConfig{
		view: view,
	}
	headersConf.add(context.Background(), "X-Test-Header", false)
	headersConf.add(context.Background(), "X-Vault-Header", false)

	logInput := &logical.LogInput{
		Auth:     auth,
		Request:  reqCopy,
		OuterErr: respErr,
	}
	ctx := namespace.RootContext(context.Background())
	err = b.LogRequest(ctx, logInput, headersConf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expected := map[string][]string{
		"x-test-header":  {"foo"},
		"x-vault-header": {"bar"},
	}

	for _, a := range []*corehelpers.NoopAudit{a1, a2} {
		if !reflect.DeepEqual(a.ReqHeaders[0], expected) {
			t.Fatalf("Bad audited headers: %#v", a.Req[0].Headers)
		}
	}

	// Should still work with one failing backend
	a1.ReqErr = errors.New("failed")
	logInput = &logical.LogInput{
		Auth:     auth,
		Request:  req,
		OuterErr: respErr,
	}
	err = b.LogRequest(ctx, logInput, headersConf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should FAIL work with both failing backends
	a2.ReqErr = errors.New("failed")
	err = b.LogRequest(ctx, logInput, headersConf)
	if !errwrap.Contains(err, "no audit backend succeeded in logging the request") {
		t.Fatalf("err: %v", err)
	}
}
