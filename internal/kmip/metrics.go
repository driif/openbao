// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
)

// listenerMetrics owns the active certificate set. Closed subjects stop being
// emitted; Prometheus retains the last sample until its configured expiration.
type listenerMetrics struct {
	sink        *metricsutil.ClusterMetricSink
	address     string
	mu          sync.Mutex
	clients     map[*wireConn]*x509.Certificate
	certificate func() *x509.Certificate
}

func (m *listenerMetrics) labels(extra ...metricsutil.Label) []metricsutil.Label {
	return append(extra, metricsutil.Label{Name: "listener", Value: m.address})
}

func (m *listenerMetrics) counter(name string, extra ...metricsutil.Label) {
	m.sink.IncrCounterWithLabels([]string{"kmip", name}, 1, m.labels(extra...))
}

func (m *listenerMetrics) gauge(name string, value float32, extra ...metricsutil.Label) {
	m.sink.SetGaugeWithLabels([]string{"kmip", name}, value, m.labels(extra...))
}

func (m *listenerMetrics) operation(operation, outcome, errorReason string, started time.Time) {
	op := metricsutil.Label{Name: "operation", Value: operation}
	m.counter("operations", op, metricsutil.Label{Name: "outcome", Value: outcome})
	m.sink.MeasureSinceWithLabels([]string{"kmip", "operation_duration"}, started, m.labels(op))
	if outcome != "success" {
		m.counter("errors", metricsutil.Label{Name: "reason", Value: errorReason})
	}
}

func (m *listenerMetrics) refresh() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.certificate != nil {
		if cert := m.certificate(); cert != nil {
			m.gauge("server_certificate_expiry_seconds", float32(cert.NotAfter.Sub(now).Seconds()))
		}
	}
	earliest := make(map[string]time.Time)
	for _, cert := range m.clients {
		subject := cert.Subject.String()
		if expiry, ok := earliest[subject]; !ok || cert.NotAfter.Before(expiry) {
			earliest[subject] = cert.NotAfter
		}
	}
	for subject, expiry := range earliest {
		m.gauge("client_certificate_expiry_seconds", float32(expiry.Sub(now).Seconds()), metricsutil.Label{Name: "subject", Value: subject})
	}
}

func reasonLabel(reason string) metricsutil.Label {
	return metricsutil.Label{Name: "reason", Value: reason}
}
