// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestKmipRole_ReadEmpty(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "kmip/roles/myrole",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestKmipRole_WriteAndRead(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/myrole",
		Data: map[string]interface{}{
			"cert_subject_dn":    "CN=client1,O=Acme",
			"allowed_operations": "Create,Get,Locate",
			"allowed_key_names":  "key1,key2",
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "kmip/roles/myrole",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, "CN=client1,O=Acme", resp.Data["cert_subject_dn"])
	require.ElementsMatch(t, []string{"Create", "Get", "Locate"}, resp.Data["allowed_operations"])
	require.ElementsMatch(t, []string{"key1", "key2"}, resp.Data["allowed_key_names"])
}

func TestKmipRole_PartialUpdate(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// Write initial role
	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/myrole",
		Data: map[string]interface{}{
			"cert_subject_dn":    "CN=client1,O=Acme",
			"allowed_operations": "Create,Get",
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Update only allowed_operations
	updateReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/myrole",
		Data: map[string]interface{}{
			"allowed_operations": "Create,Get,Destroy",
		},
	}
	resp, err := b.HandleRequest(context.Background(), updateReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "kmip/roles/myrole",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// cert_subject_dn should be preserved
	require.Equal(t, "CN=client1,O=Acme", resp.Data["cert_subject_dn"])
	require.ElementsMatch(t, []string{"Create", "Get", "Destroy"}, resp.Data["allowed_operations"])
}

func TestKmipRole_Delete(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// Create a role
	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/myrole",
		Data: map[string]interface{}{
			"cert_subject_dn": "CN=client1,O=Acme",
		},
	}
	_, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)

	// Delete it
	deleteReq := &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      "kmip/roles/myrole",
	}
	resp, err := b.HandleRequest(context.Background(), deleteReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Confirm it's gone
	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "kmip/roles/myrole",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestKmipRole_DeleteNonExistent(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	deleteReq := &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      "kmip/roles/doesnotexist",
	}
	resp, err := b.HandleRequest(context.Background(), deleteReq)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestKmipRole_List(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// Empty list
	listReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "kmip/roles/",
	}
	resp, err := b.HandleRequest(context.Background(), listReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Data["keys"])

	// Create a couple roles
	for _, name := range []string{"alpha", "beta", "gamma"} {
		req := &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "kmip/roles/" + name,
			Data: map[string]interface{}{
				"cert_subject_dn": "CN=" + name,
			},
		}
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}

	resp, err = b.HandleRequest(context.Background(), listReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	require.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, keys)
}

func TestKmipRole_AllowedKeyNamesEmpty(t *testing.T) {
	b, storage := createBackendWithSysView(t)

	// Role without allowed_key_names (means all keys allowed)
	writeReq := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/admin",
		Data: map[string]interface{}{
			"cert_subject_dn":    "CN=admin,O=Acme",
			"allowed_operations": "Create,Get,Locate,Destroy",
		},
	}
	resp, err := b.HandleRequest(context.Background(), writeReq)
	require.NoError(t, err)
	require.Nil(t, resp)

	readReq := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "kmip/roles/admin",
	}
	resp, err = b.HandleRequest(context.Background(), readReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// allowed_key_names should be empty (all keys allowed)
	require.Empty(t, resp.Data["allowed_key_names"])
}
