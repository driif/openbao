// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestPolicy_Metadata(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	p := &Policy{Name: "test"}

	record, err := p.LoadMetadata(ctx, storage)
	require.NoError(t, err)
	require.Nil(t, record)

	require.NoError(t, p.StoreMetadata(ctx, storage, &MetadataRecord{Version: 1, Data: map[string]string{"a": "1"}}))
	record, err = p.LoadMetadata(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, &MetadataRecord{Version: 1, Data: map[string]string{"a": "1"}}, record)

	// The record sits beside policy/ and archive/.
	entry, err := storage.Get(ctx, "metadata/test")
	require.NoError(t, err)
	require.NotNil(t, entry)

	// A nil record is rejected; an empty record keeps its version.
	require.Error(t, p.StoreMetadata(ctx, storage, nil))
	require.NoError(t, p.StoreMetadata(ctx, storage, &MetadataRecord{Version: 2}))
	entry, err = storage.Get(ctx, "metadata/test")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.JSONEq(t, `{"version":2,"data":{}}`, string(entry.Value))
}

func TestLockManager_MetadataBackupRestoreDelete(t *testing.T) {
	for _, useCache := range []bool{true, false} {
		lm, err := NewLockManager(useCache, 0)
		require.NoError(t, err)
		testMetadataBackupRestoreDelete(t, lm)
	}
}

func testMetadataBackupRestoreDelete(t *testing.T, lm *LockManager) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	record := &MetadataRecord{Version: 3, Data: map[string]string{"a": "1,2"}}

	newKey := func(name string) *Policy {
		t.Helper()
		p, _, err := lm.GetPolicy(ctx, PolicyRequest{
			Upsert:               true,
			Storage:              storage,
			KeyType:              KeyType_AES256_GCM96,
			Name:                 name,
			Exportable:           true,
			AllowPlaintextBackup: true,
		}, rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, p)
		p.Unlock()
		return p
	}
	loadMetadata := func(name string) *MetadataRecord {
		t.Helper()
		got, err := (&Policy{Name: name}).LoadMetadata(ctx, storage)
		require.NoError(t, err)
		return got
	}
	withoutMetadata := func(backup string) string {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(backup)
		require.NoError(t, err)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &fields))
		delete(fields, "metadata")
		raw, err = json.Marshal(fields)
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(raw)
	}

	p := newKey("meta")
	require.NoError(t, p.StoreMetadata(ctx, storage, record))

	backup, err := lm.BackupPolicy(ctx, storage, "meta")
	require.NoError(t, err)

	// Restoring under a new name restores no record: the record describes
	// the key it was backed up from, and would attach that key's relations
	// to another one.
	require.NoError(t, lm.RestorePolicy(ctx, storage, "meta-copy", backup, false))
	require.Nil(t, loadMetadata("meta-copy"))

	// Deleting the key deletes its record.
	p.DeletionAllowed = true
	require.NoError(t, p.Persist(ctx, storage))
	require.NoError(t, lm.DeletePolicy(ctx, storage, "meta"))
	require.Nil(t, loadMetadata("meta"))

	require.NoError(t, lm.RestorePolicy(ctx, storage, "", backup, false))
	require.Equal(t, uint64(4), loadMetadata("meta").Version)
	require.Equal(t, record.Data, loadMetadata("meta").Data)

	// A key without a record backs up without the field.
	newKey("plain")
	plain, err := lm.BackupPolicy(ctx, storage, "plain")
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(plain)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"metadata"`)

	// A backup without the field, such as one taken before metadata
	// existed, writes no record, and a forced restore of it keeps the
	// record already there.
	require.NoError(t, lm.RestorePolicy(ctx, storage, "legacy", withoutMetadata(backup), false))
	require.Nil(t, loadMetadata("legacy"))
	require.NoError(t, lm.RestorePolicy(ctx, storage, "", withoutMetadata(backup), true))
	require.Equal(t, &MetadataRecord{Version: 4, Data: record.Data}, loadMetadata("meta"))

	// A forced restore under the backup's own name replaces the record
	// above both the existing version and the backup version.
	other := &MetadataRecord{Version: 9, Data: map[string]string{"other": "9"}}
	require.NoError(t, (&Policy{Name: "meta"}).StoreMetadata(ctx, storage, other))
	require.NoError(t, lm.RestorePolicy(ctx, storage, "", backup, true))
	require.Equal(t, uint64(10), loadMetadata("meta").Version)
	require.Equal(t, record.Data, loadMetadata("meta").Data)

	// A forced restore under a new name leaves the target's record alone.
	require.NoError(t, (&Policy{Name: "legacy"}).StoreMetadata(ctx, storage, other))
	require.NoError(t, lm.RestorePolicy(ctx, storage, "legacy", backup, true))
	require.Equal(t, other, loadMetadata("legacy"))
}

// A writer can hold a policy that a delete finished with while it waited for
// the lock. Writing then would replace the record of a key created since
// under the same name.
func TestPolicy_StoreMetadataRefusesDeletedPolicy(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	lm, err := NewLockManager(true, 0)
	require.NoError(t, err)

	p, _, err := lm.GetPolicy(ctx, PolicyRequest{
		Upsert:  true,
		Storage: storage,
		KeyType: KeyType_AES256_GCM96,
		Name:    "k",
	}, rand.Reader)
	require.NoError(t, err)
	p.DeletionAllowed = true
	require.NoError(t, p.Persist(ctx, storage))
	p.Unlock()
	require.NoError(t, lm.DeletePolicy(ctx, storage, "k"))

	require.Error(t, p.StoreMetadata(ctx, storage, &MetadataRecord{Version: 1, Data: map[string]string{"a": "1"}}))
	got, err := (&Policy{Name: "k"}).LoadMetadata(ctx, storage)
	require.NoError(t, err)
	require.Nil(t, got)
}

// A forced restore that Persist rejects must leave the existing key's
// record alone, instead of pairing the old key with the backup's record.
func TestLockManager_RestoreRejectedKeepsMetadata(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	lm, err := NewLockManager(true, 0)
	require.NoError(t, err)

	newKey := func(name string) *Policy {
		t.Helper()
		p, _, err := lm.GetPolicy(ctx, PolicyRequest{
			Upsert:               true,
			Storage:              storage,
			KeyType:              KeyType_AES256_GCM96,
			Name:                 name,
			Exportable:           true,
			AllowPlaintextBackup: true,
		}, rand.Reader)
		require.NoError(t, err)
		p.Unlock()
		return p
	}
	target := newKey("target")
	kept := &MetadataRecord{Version: 1, Data: map[string]string{"kept": "1"}}
	require.NoError(t, target.StoreMetadata(ctx, storage, kept))

	source := newKey("source")
	require.NoError(t, source.StoreMetadata(ctx, storage, &MetadataRecord{Version: 1, Data: map[string]string{"other": "2"}}))
	backup, err := lm.BackupPolicy(ctx, storage, "source")
	require.NoError(t, err)

	// A backup whose versions disagree passes decoding and fails Persist.
	raw, err := base64.StdEncoding.DecodeString(backup)
	require.NoError(t, err)
	var fields map[string]map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	fields["policy"]["min_decryption_version"] = 99
	raw, err = json.Marshal(fields)
	require.NoError(t, err)

	err = lm.RestorePolicy(ctx, storage, "target", base64.StdEncoding.EncodeToString(raw), true)
	require.Error(t, err)

	got, err := (&Policy{Name: "target"}).LoadMetadata(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, kept, got)
}

// A restored empty record is present and advances above both histories.
func TestLockManager_RestoreEmptyMetadata(t *testing.T) {
	for _, cached := range []bool{false, true} {
		lm, err := NewLockManager(cached, 0)
		require.NoError(t, err)
		storage := &logical.InmemStorage{}
		p, _, err := lm.GetPolicy(t.Context(), PolicyRequest{
			Storage: storage, Name: "k", Upsert: true, KeyType: KeyType_AES256_GCM96,
			Exportable: true, AllowPlaintextBackup: true,
		}, rand.Reader)
		require.NoError(t, err)
		require.NoError(t, p.StoreMetadata(t.Context(), storage, &MetadataRecord{Version: 7}))
		p.Unlock()
		backup, err := lm.BackupPolicy(t.Context(), storage, "k")
		require.NoError(t, err)
		for _, version := range []uint64{3, 20} {
			require.NoError(t, p.StoreMetadata(t.Context(), storage, &MetadataRecord{Version: version, Data: map[string]string{"x": "y"}}))
			require.NoError(t, lm.RestorePolicy(t.Context(), storage, "", backup, true))
			record, err := p.LoadMetadata(t.Context(), storage)
			require.NoError(t, err)
			require.NotNil(t, record)
			require.Equal(t, map[string]string{}, record.Data)
			require.Equal(t, max(uint64(7), version)+1, record.Version)
		}
		require.NoError(t, p.StoreMetadata(t.Context(), storage, &MetadataRecord{Version: math.MaxUint64}))
		require.ErrorContains(t, lm.RestorePolicy(t.Context(), storage, "", backup, true), "version overflow")
	}
}

type metadataRestoreStorage struct {
	logical.InmemStorage
	mu        sync.Mutex
	beforePut func(*logical.StorageEntry)
}

func (s *metadataRestoreStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	s.mu.Lock()
	before := s.beforePut
	s.mu.Unlock()
	if before != nil {
		before(entry)
	}
	return s.InmemStorage.Put(ctx, entry)
}

// A writer that finds the restored policy in cache waits until its record
// is restored. It must read the restored version before changing it.
func TestLockManager_RestoreMetadataConcurrentWriter(t *testing.T) {
	lm, err := NewLockManager(true, 0)
	require.NoError(t, err)
	s := &metadataRestoreStorage{}
	p, _, err := lm.GetPolicy(t.Context(), PolicyRequest{
		Storage: s, Name: "k", Upsert: true, KeyType: KeyType_AES256_GCM96,
		Exportable: true, AllowPlaintextBackup: true,
	}, rand.Reader)
	require.NoError(t, err)
	require.NoError(t, p.StoreMetadata(t.Context(), s, &MetadataRecord{Version: 5, Data: map[string]string{"backup": "yes"}}))
	p.Unlock()
	backup, err := lm.BackupPolicy(t.Context(), s, "k")
	require.NoError(t, err)
	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	var once sync.Once
	s.beforePut = func(entry *logical.StorageEntry) {
		if entry.Key != "metadata/k" {
			return
		}
		once.Do(func() {
			cached, ok := lm.cache.Load("k")
			require.True(t, ok)
			locked := cached.(*Policy).l.TryLock()
			if locked {
				cached.(*Policy).l.Unlock()
			}
			require.False(t, locked, "restored policy must stay locked through the metadata write")
			go func() {
				close(writerStarted)
				writer, _, err := lm.GetPolicyExclusive(t.Context(), PolicyRequest{Storage: s, Name: "k"}, rand.Reader)
				if err != nil {
					writerDone <- err
					return
				}
				defer writer.Unlock()
				record, err := writer.LoadMetadata(t.Context(), s)
				if err == nil {
					record.Version++
					record.Data["writer"] = "yes"
					err = writer.StoreMetadata(t.Context(), s, record)
				}
				writerDone <- err
			}()
			<-writerStarted
		})
	}
	require.NoError(t, lm.RestorePolicy(t.Context(), s, "", backup, true))
	require.NoError(t, <-writerDone)
	record, err := p.LoadMetadata(t.Context(), s)
	require.NoError(t, err)
	require.Equal(t, uint64(7), record.Version)
	require.Equal(t, map[string]string{"backup": "yes", "writer": "yes"}, record.Data)
}

// A forced restore over a cached key keeps the replaced policy's mutex, so a
// writer still holding the old policy object and one holding the restored
// object are serialized: two metadata writes cannot both pass the same cas.
func TestLockManager_RestoreKeepsPolicyMutex(t *testing.T) {
	ctx := t.Context()
	storage := &logical.InmemStorage{}
	lm, err := NewLockManager(true, 0)
	require.NoError(t, err)

	p, _, err := lm.GetPolicy(ctx, PolicyRequest{
		Upsert:               true,
		Storage:              storage,
		KeyType:              KeyType_AES256_GCM96,
		Name:                 "k",
		Exportable:           true,
		AllowPlaintextBackup: true,
	}, rand.Reader)
	require.NoError(t, err)
	p.Unlock()

	backup, err := lm.BackupPolicy(ctx, storage, "k")
	require.NoError(t, err)
	require.NoError(t, lm.RestorePolicy(ctx, storage, "k", backup, true))

	restored, _, err := lm.GetPolicy(ctx, PolicyRequest{Storage: storage, Name: "k"}, rand.Reader)
	require.NoError(t, err)
	restored.Unlock()
	require.NotSame(t, p, restored)
	require.Same(t, p.l, restored.l)
}
