// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	"github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
)

// TestReplay sends the request messages recorded under testdata/<client>/,
// NNN.req.ttlv in order, to a kmip listener over one connection, and
// compares each response with NNN.resp.ttlv once both are masked. A trace
// from another client drops in as a new directory.
func TestReplay(t *testing.T) {
	clients, err := os.ReadDir("testdata")
	require.NoError(t, err)
	for _, client := range clients {
		if !client.IsDir() {
			continue
		}
		t.Run(client.Name(), func(t *testing.T) {
			replay(t, filepath.Join("testdata", client.Name()))
		})
	}
}

func replay(t *testing.T, dir string) {
	requests, err := filepath.Glob(filepath.Join(dir, "*.req.ttlv"))
	require.NoError(t, err)
	require.NotEmpty(t, requests, "no fixtures in %s", dir)
	slices.Sort(requests)

	core, pki := newKMIPCluster(t)
	addr := serveKMIP(t, core, "auth/cert", pki)
	conn := dialTLS(t, addr, pki)

	for _, reqFile := range requests {
		request, err := os.ReadFile(reqFile)
		require.NoError(t, err)
		recorded, err := os.ReadFile(strings.TrimSuffix(reqFile, ".req.ttlv") + ".resp.ttlv")
		require.NoError(t, err)

		_, err = conn.Write(request)
		require.NoError(t, err)
		got := readMessage(t, conn)

		want, have := decodeResponse(t, recorded), decodeResponse(t, got)
		require.Equal(t, string(ttlv.MarshalText(want)), string(ttlv.MarshalText(have)), reqFile)
	}
}

// newKMIPCluster starts one node with transit and cert auth set up for the
// test PKI's client.
func newKMIPCluster(t *testing.T) (*vault.TestClusterCore, testPKI) {
	t.Helper()

	cluster := vault.NewTestCluster(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{"cert": cert.Factory},
		LogicalBackends:    map[string]logical.Factory{"transit": transit.Factory},
	}, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	t.Cleanup(cluster.Cleanup)
	core := testhelpers.WaitForActiveNode(t, cluster)

	pki := newPKI(t)
	setUpTenant(t, core.Client, pki)
	return core, pki
}

func dialTLS(t *testing.T, addr string, pki testPKI) *tls.Conn {
	t.Helper()

	cert, err := tls.X509KeyPair(pki.client.Pem, pki.client.PrivKey.Pem)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pki.ca.Pem))
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "localhost",
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Minute)))
	return conn
}

// readMessage reads one TTLV item: a tag, a type and a length in eight
// bytes, then the value.
func readMessage(t *testing.T, r io.Reader) []byte {
	t.Helper()

	header := make([]byte, 8)
	_, err := io.ReadFull(r, header)
	require.NoError(t, err)
	value := make([]byte, binary.BigEndian.Uint32(header[4:]))
	_, err = io.ReadFull(r, value)
	require.NoError(t, err)
	return append(header, value...)
}

// decodeResponse decodes a response message and masks what differs between
// runs: the time stamp, dates, and key material.
func decodeResponse(t *testing.T, raw []byte) *kmiplib.ResponseMessage {
	t.Helper()

	var msg kmiplib.ResponseMessage
	require.NoError(t, ttlv.UnmarshalTTLV(raw, &msg))

	msg.Header.TimeStamp = time.Time{}
	for i := range msg.BatchItem {
		switch p := msg.BatchItem[i].ResponsePayload.(type) {
		case *payloads.GetResponsePayload:
			if key, ok := p.Object.(*kmiplib.SymmetricKey); ok && key.KeyBlock.KeyValue != nil && key.KeyBlock.KeyValue.Plain != nil {
				key.KeyBlock.KeyValue.Plain.KeyMaterial = kmiplib.KeyMaterial{}
			}
		case *payloads.GetAttributesResponsePayload:
			for j := range p.Attribute {
				if _, ok := p.Attribute[j].AttributeValue.(time.Time); ok {
					p.Attribute[j].AttributeValue = time.Time{}
				}
			}
		}
	}
	return &msg
}
