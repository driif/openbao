// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// metadataOps builds an operations list for a metadata write.
func metadataOps(ops ...map[string]any) map[string]any {
	list := make([]any, len(ops))
	for i, op := range ops {
		list[i] = op
	}
	return map[string]any{"operations": list}
}

func addOp(entry, value string) map[string]any {
	return map[string]any{"op": "add", "scope": "app", "entry": entry, "value": value}
}

func writeMetadata(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/" + name + "/metadata",
		Operation: logical.UpdateOperation,
		Storage:   s,
		Data:      data,
	})
}

func readMetadata(t *testing.T, b *backend, s logical.Storage, name string) metadataRecord {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/" + name + "/metadata",
		Operation: logical.ReadOperation,
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%v", resp.Error())
	return resp.Data["metadata"].(metadataRecord)
}

func createKey(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any) {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/" + name,
		Operation: logical.UpdateOperation,
		Storage:   s,
		Data:      data,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "%v", resp)
}

func readKey(t *testing.T, b *backend, s logical.Storage, name string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/" + name,
		Operation: logical.ReadOperation,
		Storage:   s,
	})
	require.NoError(t, err)
	return resp
}

func requireWrite(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any) {
	t.Helper()
	resp, err := writeMetadata(t, b, s, name, data)
	require.NoError(t, err)
	require.False(t, resp.IsError(), "%v", resp.Error())
}

func requireWriteError(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any, msg string) {
	t.Helper()
	resp, err := writeMetadata(t, b, s, name, data)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.NotNil(t, resp)
	require.ErrorContains(t, resp.Error(), msg)
}

func TestTransit_KeyMetadata_WriteReadDelete(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)

	// A key without a record reads as empty, and its key read has no field.
	require.Empty(t, readMetadata(t, b, s, "k"))
	require.NotContains(t, readKey(t, b, s, "k").Data, "metadata")

	requireWrite(t, b, s, "k", metadataOps(addOp("a", "1"), addOp("a", "2"), addOp("b", "x")))
	want := metadataRecord{"app": {"a": {"1", "2"}, "b": {"x"}}}
	require.Equal(t, want, readMetadata(t, b, s, "k"))
	require.Equal(t, want, readKey(t, b, s, "k").Data["metadata"])

	// The record goes with the key.
	_, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/k/config",
		Operation: logical.UpdateOperation,
		Storage:   s,
		Data:      map[string]any{"deletion_allowed": true},
	})
	require.NoError(t, err)
	_, err = b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/k",
		Operation: logical.DeleteOperation,
		Storage:   s,
	})
	require.NoError(t, err)
	entry, err := s.Get(t.Context(), "metadata/k")
	require.NoError(t, err)
	require.Nil(t, entry)

	createKey(t, b, s, "k", nil)
	require.Empty(t, readMetadata(t, b, s, "k"))
}

func TestTransit_KeyMetadata_MissingKey(t *testing.T) {
	b, s := createBackendWithStorage(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/missing/metadata",
		Operation: logical.ReadOperation,
		Storage:   s,
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	requireWriteError(t, b, s, "missing", metadataOps(addOp("a", "1")), "key not found")
}

func TestTransit_KeyMetadata_Operations(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	requireWrite(t, b, s, "k", metadataOps(addOp("a", "1"), addOp("a", "2"), addOp("a", "3"), addOp("b", "x")))

	// Delete one value by index, then a whole entry. Deleting an absent
	// entry is a no-op, so a repeated delete is safe.
	requireWrite(t, b, s, "k", metadataOps(
		map[string]any{"op": "delete", "scope": "app", "entry": "a", "index": 1},
		map[string]any{"op": "delete", "scope": "app", "entry": "b"},
		map[string]any{"op": "delete", "scope": "app", "entry": "never"},
	))
	require.Equal(t, metadataRecord{"app": {"a": {"1", "3"}}}, readMetadata(t, b, s, "k"))

	requireWriteError(t, b, s, "k", metadataOps(
		map[string]any{"op": "delete", "scope": "app", "entry": "a", "index": 5},
	), `entry "a" in scope "app" has no value at index 5`)

	// Delete then add replaces an entry, and repeating it changes nothing.
	replace := metadataOps(
		map[string]any{"op": "delete", "scope": "app", "entry": "a"},
		addOp("a", "9"),
	)
	requireWrite(t, b, s, "k", replace)
	requireWrite(t, b, s, "k", replace)
	require.Equal(t, metadataRecord{"app": {"a": {"9"}}}, readMetadata(t, b, s, "k"))

	// link sets a single key name.
	requireWrite(t, b, s, "k", metadataOps(map[string]any{"op": "link", "scope": "app", "entry": "next", "value": "k.2"}))
	requireWrite(t, b, s, "k", metadataOps(map[string]any{"op": "link", "scope": "app", "entry": "next", "value": "k.3"}))
	require.Equal(t, []string{"k.3"}, readMetadata(t, b, s, "k")["app"]["next"])
	requireWriteError(t, b, s, "k", metadataOps(
		map[string]any{"op": "link", "scope": "app", "entry": "next", "value": "../other"},
	), `link value "../other" is not a key name`)

	requireWriteError(t, b, s, "k", metadataOps(map[string]any{"op": "rename", "scope": "app", "entry": "a"}), `unknown op "rename"`)
	requireWriteError(t, b, s, "k", metadataOps(map[string]any{"op": "add", "entry": "a", "value": "1"}), "needs a scope and an entry")
	requireWriteError(t, b, s, "k", metadataOps(map[string]any{"op": "add", "scope": "app", "entry": "a", "bogus": true}), "invalid operations")

	// A list with a failing operation applies nothing.
	requireWriteError(t, b, s, "k", metadataOps(
		addOp("c", "1"),
		map[string]any{"op": "rename", "scope": "app", "entry": "a"},
	), "operation 1")
	require.NotContains(t, readMetadata(t, b, s, "k")["app"], "c")

	// Emptying the record deletes it.
	requireWrite(t, b, s, "k", metadataOps(
		map[string]any{"op": "delete", "scope": "app", "entry": "a"},
		map[string]any{"op": "delete", "scope": "app", "entry": "next"},
	))
	entry, err := s.Get(t.Context(), "metadata/k")
	require.NoError(t, err)
	require.Nil(t, entry)
}

func TestTransit_KeyMetadata_Claim(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)

	claim := func(value, expected string) map[string]any {
		return metadataOps(map[string]any{"op": "claim", "scope": "app", "entry": "owner", "value": value, "expected": expected})
	}

	requireWrite(t, b, s, "k", claim("a", ""))
	// Claiming the value already held succeeds and changes nothing.
	requireWrite(t, b, s, "k", claim("a", ""))
	// A second claim on an entry held by another value fails and names
	// the holder.
	requireWriteError(t, b, s, "k", claim("b", ""), `entry "owner" in scope "app" is held by "a"`)
	requireWriteError(t, b, s, "k", claim("b", "c"), `is held by "a"`)
	// A claim that expects the holder replaces it.
	requireWrite(t, b, s, "k", claim("b", "a"))
	require.Equal(t, []string{"b"}, readMetadata(t, b, s, "k")["app"]["owner"])
	// So the holder cannot move back.
	requireWriteError(t, b, s, "k", claim("a", "x"), `is held by "b"`)
}

func TestTransit_KeyMetadata_Bounds(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)

	requireWriteError(t, b, s, "k", metadataOps(addOp("a", strings.Repeat("v", metadataMaxValueBytes))),
		`a value of entry "a" in scope "app" is 8194 bytes; the limit is 8192`)

	var entries []map[string]any
	for i := range metadataMaxEntries + 1 {
		entries = append(entries, addOp(fmt.Sprintf("e%d", i), "1"))
	}
	requireWriteError(t, b, s, "k", metadataOps(entries...), `scope "app" holds 129 entries; the limit is 128`)

	var scopes []map[string]any
	for i := range metadataMaxScopes + 1 {
		scopes = append(scopes, map[string]any{"op": "add", "scope": fmt.Sprintf("s%d", i), "entry": "a", "value": "1"})
	}
	requireWriteError(t, b, s, "k", metadataOps(scopes...), "metadata holds 9 scopes; the limit is 8")

	// Every value and entry is within its guard, but the total is not.
	big := strings.Repeat("v", 8000)
	var total []map[string]any
	for range 9 {
		total = append(total, addOp("a", big))
	}
	requireWriteError(t, b, s, "k", metadataOps(total...), "the limit is 65536")

	require.Empty(t, readMetadata(t, b, s, "k"))
}

func TestTransit_KeyMetadata_SoftDeletedKey(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	_, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/k/soft-delete",
		Operation: logical.DeleteOperation,
		Storage:   s,
	})
	require.NoError(t, err)

	requireWrite(t, b, s, "k", metadataOps(addOp("a", "1")))
	require.Equal(t, metadataRecord{"app": {"a": {"1"}}}, readMetadata(t, b, s, "k"))
}

func TestTransit_KeyMetadata_BackupRestore(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", map[string]any{"exportable": true, "allow_plaintext_backup": true})
	requireWrite(t, b, s, "k", metadataOps(addOp("a", "1")))

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "backup/k",
		Operation: logical.ReadOperation,
		Storage:   s,
	})
	require.NoError(t, err)
	backup := resp.Data["backup"].(string)

	restore := func(name string, force bool) {
		t.Helper()
		resp, err := b.HandleRequest(t.Context(), &logical.Request{
			Path:      "restore/" + name,
			Operation: logical.UpdateOperation,
			Storage:   s,
			Data:      map[string]any{"backup": backup, "force": force},
		})
		require.NoError(t, err)
		require.Nil(t, resp)
	}

	// Under the backup's own name, the record comes back.
	requireWrite(t, b, s, "k", metadataOps(addOp("b", "2")))
	restore("k", true)
	require.Equal(t, metadataRecord{"app": {"a": {"1"}}}, readMetadata(t, b, s, "k"))

	// Under a new name it does not: it describes the key it came from.
	restore("k-restored", false)
	require.Empty(t, readMetadata(t, b, s, "k-restored"))
}

// A write that waited for the lock while the key was deleted must not store
// a record: the next key of that name would inherit it. Deleting the policy
// entry under a cached policy leaves the same state the race does.
func TestTransit_KeyMetadata_WriteAfterDeleteRefused(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	requireWrite(t, b, s, "k", metadataOps(addOp("a", "1")))
	require.NoError(t, s.Delete(t.Context(), "policy/k"))

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Path:      "keys/k/metadata",
		Operation: logical.UpdateOperation,
		Storage:   s,
		Data:      metadataOps(addOp("b", "2")),
	})
	require.Error(t, err)
	require.Contains(t, resp.Error().Error(), "key not found")

	entry, err := s.Get(t.Context(), "metadata/k")
	require.NoError(t, err)
	var stored map[string]map[string][]string
	require.NoError(t, json.Unmarshal(entry.Value, &stored))
	require.NotContains(t, stored["app"], "b")
}

// Writers on one key never lose each other's updates, because each write
// reads, changes and stores the record under the key's exclusive lock.
func TestTransit_KeyMetadata_ConcurrentWriters(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)

	const writers = 32
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			resp, err := writeMetadata(t, b, s, "k", metadataOps(addOp(fmt.Sprintf("w%d", i), "1")))
			if err != nil || resp.IsError() {
				t.Errorf("writer %d: %v %v", i, err, resp)
			}
		})
	}
	wg.Wait()

	record := readMetadata(t, b, s, "k")
	require.Len(t, record["app"], writers)
}
