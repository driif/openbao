// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

//go:build kmipdump

package kmip_test

import (
	"os"
	"path/filepath"
	"testing"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"
)

// TestRecordSmokeFixtures rewrites testdata/smoke from a kmip-go client
// driving a kmip listener built with the kmipdump tag:
//
//	go test -tags kmipdump ./internal/kmip/ -run TestRecordSmokeFixtures
//
// TestReplay then replays the fixtures in an ordinary build.
func TestRecordSmokeFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "smoke")
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	t.Setenv("BAO_KMIP_TTLV_DUMP", dir)

	core, pki := newKMIPCluster(t)
	addr := serveKMIP(t, core, "auth/cert", pki)
	smoke(t, pki.dial(t, addr, pki.client))
}

// smoke sends at least one request of each operation added for attributes
// and ReKey. Every object is named, so UIDs match between runs.
func smoke(t *testing.T, c *kmipclient.Client) {
	t.Helper()

	_, err := c.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("app-smoke").Exec()
	require.NoError(t, err)
	_, err = c.AddAttribute("app-smoke", "x-smoke", "recorded").Exec()
	require.NoError(t, err)
	_, err = c.GetAttributeList("app-smoke").Exec()
	require.NoError(t, err)
	_, err = c.GetAttributes("app-smoke").Exec()
	require.NoError(t, err)
	_, err = c.Rekey("app-smoke").Exec()
	require.NoError(t, err)
	_, err = c.GetAttributes("app-smoke.2").Exec()
	require.NoError(t, err)
	_, err = c.Locate().WithName("app-smoke").Exec()
	require.NoError(t, err)
	_, err = c.Get("app-smoke.2").Exec()
	require.NoError(t, err)
	_, err = c.Get("app-smoke").Exec()
	require.NoError(t, err)
}
