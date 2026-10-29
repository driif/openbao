// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package keysutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

	require.NoError(t, p.StoreMetadata(ctx, storage, json.RawMessage(`{"app":{"a":["1"]}}`)))
	record, err = p.LoadMetadata(ctx, storage)
	require.NoError(t, err)
	require.JSONEq(t, `{"app":{"a":["1"]}}`, string(record))

	// The record sits beside policy/ and archive/.
	entry, err := storage.Get(ctx, "metadata/test")
	require.NoError(t, err)
	require.NotNil(t, entry)

	// An empty record deletes the object.
	require.NoError(t, p.StoreMetadata(ctx, storage, nil))
	entry, err = storage.Get(ctx, "metadata/test")
	require.NoError(t, err)
	require.Nil(t, entry)
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
	record := json.RawMessage(`{"app":{"a":["1","2"]}}`)

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
	loadMetadata := func(name string) json.RawMessage {
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
	require.JSONEq(t, string(record), string(loadMetadata("meta")))

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
	require.JSONEq(t, string(record), string(loadMetadata("meta")))

	// A forced restore under the backup's own name replaces the record.
	other := json.RawMessage(`{"app":{"other":["9"]}}`)
	require.NoError(t, (&Policy{Name: "meta"}).StoreMetadata(ctx, storage, other))
	require.NoError(t, lm.RestorePolicy(ctx, storage, "", backup, true))
	require.JSONEq(t, string(record), string(loadMetadata("meta")))

	// A forced restore under a new name leaves the target's record alone.
	require.NoError(t, (&Policy{Name: "legacy"}).StoreMetadata(ctx, storage, other))
	require.NoError(t, lm.RestorePolicy(ctx, storage, "legacy", backup, true))
	require.JSONEq(t, string(other), string(loadMetadata("legacy")))
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

	require.Error(t, p.StoreMetadata(ctx, storage, json.RawMessage(`{"app":{"a":["1"]}}`)))
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
	kept := json.RawMessage(`{"app":{"kept":["1"]}}`)
	require.NoError(t, target.StoreMetadata(ctx, storage, kept))

	source := newKey("source")
	require.NoError(t, source.StoreMetadata(ctx, storage, json.RawMessage(`{"app":{"other":["2"]}}`)))
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
	require.JSONEq(t, string(kept), string(got))
}
