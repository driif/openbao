// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"sync"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

const (
	// expiryMargin is how long before its TTL runs out a token is replaced,
	// so a request does not carry a token that lapses on the way. A token
	// with a TTL under twice this is replaced halfway through it instead.
	expiryMargin = 5 * time.Second

	// revokeTimeout bounds the token revocation when a connection closes.
	revokeTimeout = 5 * time.Second
)

type sessionKey struct{}

// session is one KMIP connection's login. It logs in on the connection's
// first operation that needs OpenBao and keeps the token in memory.
//
// kmip-go serves a connection's messages one at a time; the lock only
// matters when the connection closes during an operation.
type session struct {
	t          *translator
	peerCerts  []*x509.Certificate
	remoteAddr string

	mu        sync.Mutex
	token     string
	batch     bool
	expiry    time.Time // zero when the token does not expire
	refresh   time.Time // when to replace the token; zero with expiry
	mount     string
	keyPrefix string
	certRole  string
}

func (t *translator) newSession(peerCerts []*x509.Certificate, remoteAddr string) *session {
	return &session{t: t, peerCerts: peerCerts, remoteAddr: remoteAddr}
}

// send runs a transit request on the session's mount with the session's
// token, logging in first when there is no live token.
func (s *session) send(ctx context.Context, r request) (*reply, error) {
	token, mount, err := s.credentials(ctx)
	if err != nil {
		return nil, err
	}
	r.path = mount + "/" + r.path
	return s.t.roundTrip(ctx, s, token, r)
}

// credentials returns a live token and the transit mount it works on.
func (s *session) credentials(ctx context.Context) (token, mount string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLocked(ctx); err != nil {
		return "", "", err
	}
	if s.mount == "" {
		return "", "", kmipserver.Errorf(
			kmiplib.ResultReasonGeneralFailure,
			"no transit mount for this client: set kmip_transit_mount on cert role %q or default_transit_mount on the kmip listener",
			s.certRole,
		)
	}
	return s.token, s.mount, nil
}

// prefix returns the kmip_key_prefix of the client's cert role.
func (s *session) prefix(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLocked(ctx); err != nil {
		return "", err
	}
	return s.keyPrefix, nil
}

func (s *session) ensureLocked(ctx context.Context) error {
	if s.token != "" && (s.refresh.IsZero() || time.Now().Before(s.refresh)) {
		return nil
	}
	return s.loginLocked(ctx)
}

// revocableLocked reports whether the session holds a service token that
// has not expired yet, which a replacement or a closing connection revokes.
// Batch tokens cannot be revoked and simply expire.
func (s *session) revocableLocked() bool {
	return s.token != "" && !s.batch && (s.expiry.IsZero() || time.Now().Before(s.expiry))
}

// loginLocked logs in through the listener's cert auth mount without a role
// name, so cert auth picks the role whose constraints match the client
// certificate. The role's kmip_transit_mount and kmip_key_prefix arrive in
// the token's metadata. A token it replaces is revoked first.
func (s *session) loginLocked(ctx context.Context) error {
	if s.revocableLocked() {
		s.revoke(ctx, s.token)
	}
	s.token = ""

	rep, err := s.t.roundTrip(ctx, s, "", request{
		method: http.MethodPost,
		path:   s.t.loginPath,
		body:   map[string]any{},
	})
	if err != nil {
		return err
	}
	if !rep.ok() || rep.Auth == nil || rep.Auth.ClientToken == "" {
		reason := kmiplib.ResultReasonPermissionDenied
		if rep.status >= http.StatusInternalServerError {
			reason = kmiplib.ResultReasonGeneralFailure
		}
		return kmipserver.Errorf(reason, "login through %s failed: %s", rep.path, rep.message())
	}

	auth := rep.Auth
	s.token = auth.ClientToken
	s.batch = auth.TokenType == "batch"
	s.expiry, s.refresh = time.Time{}, time.Time{}
	if auth.LeaseDuration > 0 {
		ttl := time.Duration(auth.LeaseDuration) * time.Second
		s.expiry = time.Now().Add(ttl)
		s.refresh = s.expiry.Add(-min(expiryMargin, ttl/2))
	}
	s.certRole = auth.Metadata["cert_name"]
	s.keyPrefix = auth.Metadata["kmip_key_prefix"]
	s.mount = strings.Trim(auth.Metadata["kmip_transit_mount"], "/")
	if s.mount == "" {
		s.mount = s.t.defaultMount
	}
	return nil
}

// relogin replaces the token after a 403. The 403 may have been an ACL
// denial, leaving the old token live, so loginLocked revokes it.
func (s *session) relogin(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loginLocked(ctx)
}

// close revokes the session's service token when the connection ends. The
// connection's context is already cancelled by then, so the revocation gets
// its own deadline.
func (s *session) close(ctx context.Context) {
	s.mu.Lock()
	token, revocable := s.token, s.revocableLocked()
	s.token = ""
	s.mu.Unlock()

	if !revocable {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	s.revoke(ctx, token)
}

// revoke is best effort: a token it fails to revoke still expires.
func (s *session) revoke(ctx context.Context, token string) {
	rep, err := s.t.roundTrip(ctx, s, token, request{
		method: http.MethodPost,
		path:   "auth/token/revoke-self",
	})
	switch {
	case err != nil:
		s.t.logger.Debug("failed to revoke KMIP session token", "remote_addr", s.remoteAddr, "error", err)
	case !rep.ok():
		s.t.logger.Debug("failed to revoke KMIP session token", "remote_addr", s.remoteAddr, "status", rep.status, "error", rep.message())
	}
}
