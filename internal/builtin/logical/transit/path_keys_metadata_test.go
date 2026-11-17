// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/stretchr/testify/require"
)

func createKey(t *testing.T, b *backend, s logical.Storage, name string, data map[string]any) {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{Path: "keys/" + name, Operation: logical.UpdateOperation, Storage: s, Data: data})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "%v", resp)
}

func readKey(t *testing.T, b *backend, s logical.Storage, name string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{Path: "keys/" + name, Operation: logical.ReadOperation, Storage: s})
	require.NoError(t, err)
	return resp
}

func metadataRequest(t *testing.T, b *backend, s logical.Storage, op logical.Operation, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{Path: "keys/k/metadata", Operation: op, Storage: s, Data: data})
}

func readMetadata(t *testing.T, b *backend, s logical.Storage) *keysutil.MetadataRecord {
	t.Helper()
	resp, err := metadataRequest(t, b, s, logical.ReadOperation, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%v", resp.Error())
	return &keysutil.MetadataRecord{Version: resp.Data["version"].(uint64), Data: resp.Data["custom_metadata"].(map[string]string)}
}

func requireMetadataWrite(t *testing.T, b *backend, s logical.Storage, op logical.Operation, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := metadataRequest(t, b, s, op, data)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "%v", resp.Error())
	return resp
}

func requireMetadataError(t *testing.T, b *backend, s logical.Storage, op logical.Operation, data map[string]any, msg string) {
	t.Helper()
	resp, err := metadataRequest(t, b, s, op, data)
	require.ErrorIs(t, err, logical.ErrInvalidRequest)
	require.NotNil(t, resp)
	require.ErrorContains(t, resp.Error(), msg)
}

func TestTransit_KeyMetadata_RoundTrip(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	require.Equal(t, &keysutil.MetadataRecord{Data: map[string]string{}}, readMetadata(t, b, s))
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"a": "1", "b": "2"}, "cas": 0})
	require.Equal(t, uint64(1), readMetadata(t, b, s).Version)
	require.NotContains(t, readKey(t, b, s, "k").Data, "metadata")
	require.NotContains(t, readKey(t, b, s, "k").Data, "custom_metadata")
	requireMetadataWrite(t, b, s, logical.PatchOperation, map[string]any{"custom_metadata": map[string]any{"a": nil, "c": "3"}, "cas": 1})
	require.Equal(t, &keysutil.MetadataRecord{Version: 2, Data: map[string]string{"b": "2", "c": "3"}}, readMetadata(t, b, s))
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"d": "4"}, "cas": 2})
	require.Equal(t, &keysutil.MetadataRecord{Version: 3, Data: map[string]string{"d": "4"}}, readMetadata(t, b, s))
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.PatchOperation} {
		for _, cas := range []int{0, 1, 4} {
			requireMetadataError(t, b, s, op, map[string]any{"custom_metadata": map[string]string{"lost": "no"}, "cas": cas}, "check-and-set parameter did not match the current version")
		}
	}
	require.Equal(t, uint64(3), readMetadata(t, b, s).Version)
	requireMetadataWrite(t, b, s, logical.DeleteOperation, nil)
	require.Equal(t, &keysutil.MetadataRecord{Version: 4, Data: map[string]string{}}, readMetadata(t, b, s))
	entry, err := s.Get(t.Context(), "metadata/k")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.JSONEq(t, `{"version":4,"data":{}}`, string(entry.Value))
	requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"cas": 0}, "check-and-set parameter did not match the current version")
}

func TestTransit_KeyMetadata_ABA(t *testing.T) {
	for _, clear := range []logical.Operation{logical.DeleteOperation, logical.UpdateOperation} {
		t.Run(string(clear), func(t *testing.T) {
			b, s := createBackendWithStorage(t)
			createKey(t, b, s, "k", nil)
			// Clearing an absent record creates version 1.
			requireMetadataWrite(t, b, s, clear, map[string]any{"custom_metadata": map[string]string{}})
			require.Equal(t, &keysutil.MetadataRecord{Version: 1, Data: map[string]string{}}, readMetadata(t, b, s))
			requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"a": "1"}})
			v := readMetadata(t, b, s).Version
			requireMetadataWrite(t, b, s, clear, map[string]any{"custom_metadata": map[string]string{}})
			require.Equal(t, &keysutil.MetadataRecord{Version: v + 1, Data: map[string]string{}}, readMetadata(t, b, s))
			requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"cas": 0}, "check-and-set parameter did not match the current version")
			requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"b": "2"}})
			requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"cas": v}, "check-and-set parameter did not match the current version")

			_, err := b.HandleRequest(t.Context(), &logical.Request{Path: "keys/k/config", Operation: logical.UpdateOperation, Storage: s, Data: map[string]any{"deletion_allowed": true}})
			require.NoError(t, err)
			_, err = b.HandleRequest(t.Context(), &logical.Request{Path: "keys/k", Operation: logical.DeleteOperation, Storage: s})
			require.NoError(t, err)
			entry, err := s.Get(t.Context(), "metadata/k")
			require.NoError(t, err)
			require.Nil(t, entry)
			createKey(t, b, s, "k", nil)
			require.Equal(t, &keysutil.MetadataRecord{Data: map[string]string{}}, readMetadata(t, b, s))
		})
	}
}

func TestTransit_KeyMetadata_MissingAndDeletedKey(t *testing.T) {
	b, s := createBackendWithStorage(t)
	resp, err := metadataRequest(t, b, s, logical.ReadOperation, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.PatchOperation, logical.DeleteOperation} {
		requireMetadataError(t, b, s, op, nil, "key not found")
	}
	createKey(t, b, s, "k", nil)
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"kept": "yes"}})
	require.NoError(t, s.Delete(t.Context(), "policy/k"))
	requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"lost": "no"}}, "key not found")
	require.Equal(t, map[string]string{"kept": "yes"}, readMetadata(t, b, s).Data)
}

func TestTransit_KeyMetadata_Bounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		data map[string]string
		msg  string
	}{
		{"empty key", map[string]string{"": "x"}, "1 to 512 bytes"},
		{"key bytes", map[string]string{strings.Repeat("é", 257): "x"}, "1 to 512 bytes"},
		{"value bytes", map[string]string{"x": strings.Repeat("v", metadataMaxValueBytes+1)}, "the limit is 8192"},
		{"key count", func() map[string]string {
			m := map[string]string{}
			for i := range metadataMaxKeys + 1 {
				m[fmt.Sprint(i)] = "v"
			}
			return m
		}(), "the limit is 1024"},
		{"serialized bytes", func() map[string]string {
			m := map[string]string{}
			for i := range 9 {
				m[fmt.Sprint(i)] = strings.Repeat("v", 8000)
			}
			return m
		}(), "the limit is 65536"},
		{"escaped bytes", map[string]string{"x": strings.Repeat("\x00", metadataMaxValueBytes), "y": strings.Repeat("\x00", metadataMaxValueBytes)}, "the limit is 65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, s := createBackendWithStorage(t)
			createKey(t, b, s, "k", nil)
			requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"kept": "yes"}})
			before := readMetadata(t, b, s)
			for _, op := range []logical.Operation{logical.UpdateOperation, logical.PatchOperation} {
				requireMetadataError(t, b, s, op, map[string]any{"custom_metadata": tc.data}, tc.msg)
				require.Equal(t, before, readMetadata(t, b, s))
			}
		})
	}
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{strings.Repeat("k", 512): strings.Repeat("v", 8192)}})
	for _, value := range []any{1, true, nil, []string{"a"}} {
		requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]any{"x": value}}, "must be strings")
	}
	for _, cas := range []any{-1, 1.5} {
		resp, err := metadataRequest(t, b, s, logical.UpdateOperation, map[string]any{"cas": cas})
		require.True(t, err != nil || resp.IsError())
	}
	require.NoError(t, (&keysutil.Policy{Name: "k"}).StoreMetadata(t.Context(), s, &keysutil.MetadataRecord{Version: math.MaxUint64}))
	requireMetadataError(t, b, s, logical.DeleteOperation, nil, "version overflow")
}

func TestTransit_KeyMetadata_LargeVersion(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	const version = uint64(1 << 63)
	require.NoError(t, (&keysutil.Policy{Name: "k"}).StoreMetadata(t.Context(), s, &keysutil.MetadataRecord{Version: version}))
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{
		"custom_metadata": map[string]string{"a": "1"}, "cas": json.Number("9223372036854775808"),
	})
	require.Equal(t, version+1, readMetadata(t, b, s).Version)
}

func TestTransit_KeyMetadata_ConcurrentWriters(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	const writers = 32
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			resp, err := metadataRequest(t, b, s, logical.PatchOperation, map[string]any{"custom_metadata": map[string]string{fmt.Sprintf("w%d", i): "1"}})
			if err != nil || resp == nil || resp.IsError() {
				t.Errorf("writer %d: %v %v", i, err, resp)
			}
		})
	}
	wg.Wait()
	record := readMetadata(t, b, s)
	require.Len(t, record.Data, writers)
	require.Equal(t, uint64(writers), record.Version)
	for i := range writers {
		require.Equal(t, "1", record.Data[fmt.Sprintf("w%d", i)])
	}
}

func TestTransit_KeyMetadata_BackupRestore(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", map[string]any{"exportable": true, "allow_plaintext_backup": true})
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"a": "1"}})
	before := readMetadata(t, b, s)
	backup, err := b.HandleRequest(t.Context(), &logical.Request{Path: "backup/k", Operation: logical.ReadOperation, Storage: s})
	require.NoError(t, err)
	_, err = b.HandleRequest(t.Context(), &logical.Request{Path: "restore/k", Operation: logical.UpdateOperation, Storage: s, Data: map[string]any{"backup": backup.Data["backup"], "force": true}})
	require.NoError(t, err)
	require.Equal(t, &keysutil.MetadataRecord{Version: 2, Data: before.Data}, readMetadata(t, b, s))
	requireMetadataError(t, b, s, logical.UpdateOperation, map[string]any{"cas": before.Version}, "check-and-set parameter did not match the current version")
}

func TestTransit_KeyMetadata_SoftDeletedKey(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	_, err := b.HandleRequest(t.Context(), &logical.Request{Path: "keys/k/soft-delete", Operation: logical.DeleteOperation, Storage: s})
	require.NoError(t, err)
	requireMetadataWrite(t, b, s, logical.UpdateOperation, map[string]any{"custom_metadata": map[string]string{"a": "1"}})
	require.Equal(t, map[string]string{"a": "1"}, readMetadata(t, b, s).Data)
}

func TestTransit_KeyMetadata_PatchCapability(t *testing.T) {
	cluster := vault.NewTestCluster(t, &vault.CoreConfig{LogicalBackends: map[string]logical.Factory{"transit": Factory}}, &vault.TestClusterOptions{HandlerFunc: vaulthttp.Handler, NumCores: 1})
	cluster.Start()
	t.Cleanup(cluster.Cleanup)
	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client
	require.NoError(t, client.Sys().Mount("transit", &api.MountInput{Type: "transit"}))
	_, err := client.Logical().Write("transit/keys/k", nil)
	require.NoError(t, err)
	require.NoError(t, client.Sys().PutPolicy("metadata-update", `path "transit/keys/k/metadata" { capabilities = ["update"] }`))
	token, err := client.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"metadata-update"}})
	require.NoError(t, err)
	client.SetToken(token.Auth.ClientToken)
	for _, method := range []string{http.MethodPatch, http.MethodPost} {
		req := client.NewRequest(method, "/v1/transit/keys/k/metadata")
		req.Headers = http.Header{"Content-Type": {"application/merge-patch+json"}}
		req.Body = bytes.NewBufferString(`{"custom_metadata":{"a":"1"}}`)
		resp, err := client.RawRequestWithContext(t.Context(), req)
		if resp != nil {
			defer resp.Body.Close() //nolint:errcheck
		}
		if method == http.MethodPatch {
			require.Error(t, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
		} else {
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body struct {
				Data struct {
					Version uint64 `json:"version"`
				} `json:"data"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			require.Equal(t, uint64(1), body.Data.Version)
		}
	}
}

// A record left in the never-released draft shape decodes to version 0 with no
// data. A version that a read returns must be a usable cas, so cas=0 replaces
// the draft record instead of failing against it.
func TestTransit_KeyMetadata_DraftRecordReadsAbsent(t *testing.T) {
	b, s := createBackendWithStorage(t)
	createKey(t, b, s, "k", nil)
	require.NoError(t, s.Put(t.Context(), &logical.StorageEntry{
		Key:   "metadata/k",
		Value: []byte(`{"app":{"entry":["v"]}}`),
	}))

	record := readMetadata(t, b, s)
	require.Zero(t, record.Version)
	require.Empty(t, record.Data)

	resp, err := metadataRequest(t, b, s, logical.UpdateOperation, map[string]any{
		"custom_metadata": map[string]any{"a": "1"},
		"cas":             0,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "%v", resp.Error())
	record = readMetadata(t, b, s)
	require.Equal(t, uint64(1), record.Version)
	require.Equal(t, map[string]string{"a": "1"}, record.Data)
}
