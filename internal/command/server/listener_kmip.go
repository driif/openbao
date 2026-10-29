// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/helper/listenerutil"
)

// kmipListenerFactory opens a kmip listener: a TCP listener on port 5696
// unless configured otherwise, which only completes TLS handshakes with a
// verified client certificate. The server serves KMIP on it, not HTTP.
func kmipListenerFactory(l *configutil.Listener, logger hclog.Logger, ui cli.Ui) (net.Listener, map[string]string, listenerutil.ReloadableCertGetter, error) {
	if l.TLSDisable {
		return nil, nil, nil, errors.New("kmip listener requires TLS")
	}

	// KMIP clients authenticate with their certificate, whatever
	// tls_require_and_verify_client_cert says. It is also what makes
	// TLSConfig load tls_client_ca_file.
	l.TLSRequireAndVerifyClientCert = true

	ln, props, cg, err := newTCPListener(l, logger, ui, "127.0.0.1:5696", func(c *tls.Config) {
		// TLSConfig advertises h2 and http/1.1; KMIP is neither.
		c.NextProtos = nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	props["auth_mount"] = l.AuthMount
	if l.DefaultTransitMount != "" {
		props["default_transit_mount"] = l.DefaultTransitMount
	}
	return ln, props, cg, nil
}
