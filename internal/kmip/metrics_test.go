// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	"github.com/stretchr/testify/require"
)

func TestListenerMetrics(t *testing.T) {
	sink := metrics.NewInmemSink(time.Hour, 2*time.Hour)
	now := time.Now()
	m := &listenerMetrics{sink: metricsutil.NewClusterMetricSink("test", sink), address: "127.0.0.1:5696", clients: map[*wireConn]*x509.Certificate{}, certificate: func() *x509.Certificate { return &x509.Certificate{NotAfter: now.Add(24 * time.Hour)} }}
	first, second := new(wireConn), new(wireConn)
	m.clients[first] = &x509.Certificate{Subject: pkix.Name{CommonName: "client"}, NotAfter: now.Add(2 * time.Hour)}
	m.clients[second] = &x509.Certificate{Subject: pkix.Name{CommonName: "client"}, NotAfter: now.Add(time.Hour)}
	m.refresh()
	m.operation("Get", "success", "success", now)
	m.operation("Destroy", "PermissionDenied", "PermissionDenied", now)
	m.counter("connections_accepted")
	m.counter("connections_refused", reasonLabel("limit"))
	m.counter("connections_refused", reasonLabel("handshake"))
	m.gauge("connections_open", 2)
	gauges := map[string]float32{}
	counters := map[string]float64{}
	for _, interval := range sink.Data() {
		for name, g := range interval.Gauges {
			gauges[g.Name] = g.Value
			require.NotContains(t, name, "object-secret-uid")
		}
		for name, c := range interval.Counters {
			counters[c.Name] += c.Sum
			require.NotContains(t, name, "object-secret-uid")
		}
		for name, sample := range interval.Samples {
			require.Equal(t, "kmip.operation_duration", sample.Name)
			require.Contains(t, name, "operation=")
		}
	}
	require.InDelta(t, 3600, gauges["kmip.client_certificate_expiry_seconds"], 2)
	require.InDelta(t, 86400, gauges["kmip.server_certificate_expiry_seconds"], 2)
	require.Equal(t, float32(2), gauges["kmip.connections_open"])
	require.Equal(t, 2.0, counters["kmip.operations"])
	require.Equal(t, 1.0, counters["kmip.errors"])
	require.Equal(t, 2.0, counters["kmip.connections_refused"])
	l := &handshakeListener{metrics: m}
	require.NoError(t, l.reload(Config{ServerCertificate: func() *x509.Certificate { return &x509.Certificate{NotAfter: now.Add(48 * time.Hour)} }}))
	for _, interval := range sink.Data() {
		for _, g := range interval.Gauges {
			if g.Name == "kmip.server_certificate_expiry_seconds" {
				require.InDelta(t, 172800, g.Value, 2)
			}
		}
	}
	delete(m.clients, second)
	m.refresh()
	for _, interval := range sink.Data() {
		for _, g := range interval.Gauges {
			if strings.Contains(g.Name, "client_certificate_expiry") {
				require.InDelta(t, 7200, g.Value, 2)
			}
		}
	}
}
