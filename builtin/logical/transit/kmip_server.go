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
	srv      *kmipserver.Server
	listener net.Listener
	b        *backend
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

	// Set up client certificate verification if required
	if cfg.RequireClientCert {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
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
	} else {
		tlsCfg.ClientAuth = tls.NoClientCert
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
		srv:      srv,
		listener: listener,
		b:        b,
	}, nil
}

// Start begins serving KMIP connections in a background goroutine.
func (s *transitKmipServer) Start() error {
	go func() {
		if err := s.srv.Serve(); err != nil && err != kmipserver.ErrShutdown {
			s.b.Logger().Error("KMIP server stopped with error", "error", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the KMIP server.
func (s *transitKmipServer) Stop() error {
	return s.srv.Shutdown()
}

// Addr returns the network address the listener is bound to.
func (s *transitKmipServer) Addr() net.Addr {
	return s.listener.Addr()
}

// restartKmipServer stops any running KMIP server and starts a new one based on cfg.
// The caller must NOT hold b.kmipMu.
func (b *backend) restartKmipServer(cfg *kmipConfig) error {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	// Stop existing server if running
	if b.kmipServer != nil {
		if err := b.kmipServer.Stop(); err != nil {
			b.Logger().Warn("Error stopping existing KMIP server", "error", err)
		}
		b.kmipServer = nil
	}

	if cfg == nil || !cfg.Enabled {
		return nil
	}

	srv, err := newTransitKmipServer(cfg, b)
	if err != nil {
		return fmt.Errorf("failed to create KMIP server: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start KMIP server: %w", err)
	}

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
