// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/ovh/kmip-go/kmipserver"
)

// transitKmipServer wraps the ovh/kmip-go server with lifecycle management.
type transitKmipServer struct {
	srv        *kmipserver.Server
	listener   net.Listener
	b          *backend
	listenAddr string // configured listen address used to detect same-address restarts
}

// newTransitKmipServer creates a new KMIP server from the given config.
// It sets up TLS, creates the listener, and builds a BatchExecutor with stub handlers.
func newTransitKmipServer(cfg *kmipConfig, b *backend) (*transitKmipServer, error) {
	// Parse server certificate and key
	serverCert, err := tls.X509KeyPair([]byte(cfg.ServerCertPEM), []byte(cfg.ServerKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	// Set up CA cert pool if provided; used whether or not client certs are required.
	if cfg.TLSCACertPEM != "" {
		pool := x509.NewCertPool()
		rest := []byte(cfg.TLSCACertPEM)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}
			pool.AddCert(cert)
		}
		tlsCfg.ClientCAs = pool
	}

	if cfg.RequireClientCert {
		// Reject connections that do not present a valid client certificate.
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else if cfg.TLSCACertPEM != "" {
		// Request a client cert and verify it against the CA if presented, but
		// do not reject connections that omit one. Application-level auth
		// (authMiddleware) still requires a cert and will return PermissionDenied
		// when none is provided.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	} else {
		// Request a client cert but do not verify or require it at the TLS layer.
		// Application-level auth still requires one.
		tlsCfg.ClientAuth = tls.RequestClientCert
	}

	listener, err := tls.Listen("tcp", cfg.ListenAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener on %s: %w", cfg.ListenAddr, err)
	}

	executor := kmipserver.NewBatchExecutor()
	// Register auth middleware so every request is authenticated.
	executor.Use(authMiddleware(b))
	// Register key management operation handlers.
	registerKmipHandlers(executor, b)

	srv := kmipserver.NewServer(listener, executor)

	return &transitKmipServer{
		srv:        srv,
		listener:   listener,
		b:          b,
		listenAddr: cfg.ListenAddr,
	}, nil
}

// Start begins serving KMIP connections in a background goroutine.
func (s *transitKmipServer) Start() {
	go func() {
		if err := s.srv.Serve(); err != nil && err != kmipserver.ErrShutdown {
			s.b.Logger().Error("KMIP server stopped with error", "error", err)
		}
	}()
}

// Stop gracefully shuts down the KMIP server.
func (s *transitKmipServer) Stop() error {
	return s.srv.Shutdown()
}

// Addr returns the network address the listener is bound to.
func (s *transitKmipServer) Addr() net.Addr {
	return s.listener.Addr()
}

// restartKmipServer starts a new KMIP server based on cfg, then stops the
// previously running server. Creating the new server first means that a bad
// listen_addr or occupied port leaves the old server intact rather than
// causing an outage. The caller must NOT hold b.kmipMu.
func (b *backend) restartKmipServer(cfg *kmipConfig) error {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	if cfg == nil || !cfg.Enabled {
		// Just stop any running server; nothing new to start.
		if b.kmipServer != nil {
			if err := b.kmipServer.Stop(); err != nil {
				b.Logger().Warn("Error stopping existing KMIP server", "error", err)
			}
			b.kmipServer = nil
		}
		return nil
	}

	// When the listen address changes, bind the new server first so that a
	// startup failure (bad cert, port not available, etc.) leaves the current
	// server running rather than causing an outage.
	//
	// When the listen address stays the same (e.g. rotating the TLS certificate
	// while keeping the same port), the old server must be stopped first because
	// the OS will not allow two listeners on the same address simultaneously.
	// This introduces a brief window without a listener, but it is unavoidable.
	sameAddr := b.kmipServer != nil && b.kmipServer.listenAddr == cfg.ListenAddr

	if sameAddr {
		if err := b.kmipServer.Stop(); err != nil {
			b.Logger().Warn("Error stopping existing KMIP server", "error", err)
		}
		b.kmipServer = nil
	}

	srv, err := newTransitKmipServer(cfg, b)
	if err != nil {
		if sameAddr {
			// The old server was already stopped and cannot be restored because the OS
			// will not allow two listeners on the same address. The KMIP server is now
			// offline. The operator must write a valid configuration to re-enable it.
			b.Logger().Error("KMIP server offline after failed same-address restart; update config/kmip to re-enable", "error", err)
		}
		return fmt.Errorf("failed to create KMIP server: %w", err)
	}

	// For address-change restarts, stop the old server now that the new one is bound.
	if !sameAddr && b.kmipServer != nil {
		if err := b.kmipServer.Stop(); err != nil {
			b.Logger().Warn("Error stopping existing KMIP server", "error", err)
		}
		b.kmipServer = nil
	}

	srv.Start()
	b.kmipServer = srv
	b.Logger().Info("KMIP server started", "listen_addr", cfg.ListenAddr)
	return nil
}

// stopKmipServer stops the KMIP server if it is running.
func (b *backend) stopKmipServer() {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	if b.kmipServer != nil {
		if err := b.kmipServer.Stop(); err != nil {
			b.Logger().Warn("Error stopping KMIP server", "error", err)
		}
		b.kmipServer = nil
		b.Logger().Info("KMIP server stopped")
	}
}
