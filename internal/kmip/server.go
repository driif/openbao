package kmip

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// SupportedVersions are the KMIP protocol versions served.
var SupportedVersions = []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4}

// Core is the subset of *vault.Core used by the KMIP Server.
type Core interface {
	HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error)
}

// Config configures a KMIP listener.
type Config struct {
	// TransitMount is the path of the Transit mount serving KMIP objects,
	// e.g. "transit".
	TransitMount string
	// AuthMount is the path of the cert auth mount used to log in with the
	// client's TLS certificate, e.g. "cert".
	AuthMount string
	// AuthRole optionally pins the cert auth role ("name" login parameter).
	AuthRole string
	// Namespace is the OpenBao namespace for all requests; empty is root.
	Namespace string
	// MaxMessageSize bounds TTLV messages; zero uses the library default.
	MaxMessageSize int
}

// Set default transit mount/ auth mount paths
func (c *Config) setDefaultMounts() {
	c.TransitMount = strings.Trim(c.TransitMount, "/")
	if c.TransitMount == "" {
		c.TransitMount = "transit"
	}
	c.AuthMount = strings.Trim(c.AuthMount, "/")
	if c.AuthMount == "" {
		c.AuthMount = "cert"
	}
}

// Server serves KMIP on a single listener.
type Server struct {
	core   Core
	cfg    Config
	logger hclog.Logger
	srv    *kmipserver.Server
}

// NewServer builds a KMIP server on ln. The listener must deliver *tls.Conn
// connections (a TLS-enabled listener).
func NewServer(core Core, ln net.Listener, cfg Config, logger hclog.Logger) *Server {
	cfg.setDefaultMounts()
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	s := &Server{core: core, cfg: cfg, logger: logger}

	exec := kmipserver.NewBatchExecutor()
	exec.SetSupportedProtocolVersions(SupportedVersions...)
	s.routes(exec)

	s.srv = kmipserver.NewServer(ln, exec).
		WithConnectHook(s.onConnect).
		WithTerminateHook(s.onTerminate).
		WithMaxMessageSize(cfg.MaxMessageSize)
	return s
}

// Serve blocks until the listener is closed.
func (s *Server) Serve() error {
	s.logger.Info("serving KMIP", "transit_mount", s.cfg.TransitMount, "auth_mount", s.cfg.AuthMount)
	err := s.srv.Serve()
	if errors.Is(err, kmipserver.ErrShutdown) {
		return nil
	}
	return err
}

// Shutdown closes the listener and waits for in-flight connections.
func (s *Server) Shutdown() error {
	return s.srv.Shutdown()
}

func (s *Server) onConnect(ctx context.Context) (context.Context, error) {
	tlsState := kmipserver.TLSConnectionState(ctx)
	if tlsState == nil {
		return nil, errors.New("KMIP requires TLS")
	}
	if len(tlsState.PeerCertificates) == 0 {
		return nil, errors.New("KMIP requires a client certificate")
	}

	remote := kmipserver.RemoteAddr(ctx)
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	sess := &session{conn: &logical.Connection{RemoteAddr: host, ConnState: tlsState}}

	if err := s.login(ctx, sess); err != nil {
		s.logger.Warn("KMIP client authentication failed", "remote_addr", remote, "error", err)
		return nil, err
	}
	s.logger.Debug("KMIP client authenticated", "remote_addr", remote)
	return context.WithValue(ctx, sessionKey{}, sess), nil
}

func (s *Server) onTerminate(ctx context.Context) {
	sess := getSessionFromContext(ctx)
	if sess == nil {
		return
	}
	sess.mu.Lock()
	token, tokenType := sess.token, sess.tokenType
	sess.mu.Unlock()

	// Batch tokens cannot be revoked and are not persisted. Service tokens
	// are revoked so that short-lived KMIP connections don't accumulate
	// tokens in storage.
	if token == "" || tokenType == logical.TokenTypeBatch {
		return
	}
	req := s.createNewLogicalRequest(sess, logical.UpdateOperation, "auth/token/revoke-self", nil)
	req.ClientToken = token
	if _, err := s.core.HandleRequest(context.WithoutCancel(ctx), req); err != nil {
		s.logger.Debug("failed to revoke KMIP session token", "error", err)
	}
}
