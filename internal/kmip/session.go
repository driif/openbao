package kmip

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// session is the per-connection authentication state.
type session struct {
	conn      *logical.Connection
	mu        sync.Mutex
	token     string
	tokenType logical.TokenType
	expiresAt time.Time // zero: no expiry
}

type sessionKey struct{}

func getSessionFromContext(ctx context.Context) *session {
	sess, _ := ctx.Value(sessionKey{}).(*session)
	return sess
}

func (s *Server) getTokenFromSession(ctx context.Context, sess *session) (string, error) {
	sess.mu.Lock()
	token, exp := sess.token, sess.expiresAt
	sess.mu.Unlock()
	if token != "" && (exp.IsZero() || time.Now().Before(exp)) {
		return token, nil
	}
	if err := s.login(ctx, sess); err != nil {
		return "", kmipserver.Errorf(kmip.ResultReasonAuthenticationNotSuccessful, "re-authentication failed: %s", err)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.token, nil
}

// login authenticates the connection with the cert auth method.
func (s *Server) login(ctx context.Context, sess *session) error {
	var data map[string]any
	if s.cfg.AuthRole != "" {
		data = map[string]any{"name": s.cfg.AuthRole}
	}
	req := s.createNewLogicalRequest(sess, logical.UpdateOperation, "auth/"+s.cfg.AuthMount+"/login", data)

	resp, err := s.core.HandleRequest(ctx, req)
	if status, rerr := logical.RespondErrorCommon(req, resp, err); rerr != nil || status != 0 {
		if rerr == nil {
			rerr = fmt.Errorf("login failed with status %d", status)
		}
		return rerr
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return errors.New("cert login returned no token")
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.token = resp.Auth.ClientToken
	sess.tokenType = resp.Auth.TokenType
	sess.expiresAt = time.Time{}
	if resp.Auth.TTL > 0 {
		// Re-login a little before expiry.
		sess.expiresAt = time.Now().Add(resp.Auth.TTL - min(resp.Auth.TTL/10, 30*time.Second))
	}
	return nil
}
