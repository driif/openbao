package kmip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// Transit key names / KMIP object identifiers are restricted to this pattern;
// anything else could be used to address other paths.
var validId = regexp.MustCompile(`^\w([\w.-]*\w)?$`)

func resolveId(ctx context.Context, reqID string) (string, error) {
	id, err := kmipserver.GetIdOrPlaceholder(ctx, reqID)
	if err != nil {
		return "", kmipserver.Errorf(kmip.ResultReasonMissingData, "missing Unique Identifier and no ID placeholder is set")
	}
	if !validId.MatchString(id) {
		return "", kmipserver.Errorf(kmip.ResultReasonItemNotFound, "object %q not found", id)
	}
	return id, nil
}

func (s *Server) createNewLogicalRequest(sess *session, op logical.Operation, path string, data map[string]any) *logical.Request {
	id, _ := uuid.GenerateUUID()
	req := &logical.Request{
		ID:         id,
		Operation:  op,
		Path:       path,
		Data:       data,
		Connection: sess.conn,
		Headers:    map[string][]string{},
	}
	if s.cfg.Namespace != "" {
		req.Headers[consts.NamespaceHeaderName] = []string{s.cfg.Namespace}
	}
	return req
}

// transit sends an authenticated request to <transit mount>/<path> through
// core, and maps failures onto KMIP result reasons.
func (s *Server) handleTransitOperation(ctx context.Context, op logical.Operation, path string, data map[string]any) (map[string]any, error) {
	sess := getSessionFromContext(ctx)
	if sess == nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonAuthenticationNotSuccessful, "connection is not authenticated")
	}
	token, err := s.getTokenFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	req := s.createNewLogicalRequest(sess, op, s.cfg.TransitMount+"/"+path, data)
	req.ClientToken = token
	req.ClientTokenSource = logical.ClientTokenFromVaultHeader

	resp, err := s.core.HandleRequest(ctx, req)
	status, err := logical.RespondErrorCommon(req, resp, err)
	if err != nil || status != 0 {
		if err == nil {
			err = fmt.Errorf("request to %s failed with status %d", req.Path, status)
		}
		logical.AdjustErrorStatusCode(&status, err)
		return nil, mapLogicalCommonErrorToKmipError(status, err)
	}
	if resp == nil {
		return map[string]any{}, nil
	}
	return resp.Data, nil
}

func mapLogicalCommonErrorToKmipError(status int, err error) error {
	msg := err.Error()
	switch {
	// Restrict support kmip from active node only.
	case errors.Is(err, logical.ErrPerfStandbyPleaseForward) || strings.Contains(msg, logical.ErrPerfStandbyPleaseForward.Error()):
		return kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "this node is a standby; connect to the active node")
	}
	switch status {
	case http.StatusBadRequest:
		return kmipserver.Errorf(kmip.ResultReasonInvalidField, "%s", msg)
	case http.StatusForbidden:
		return kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "%s", msg)
	case http.StatusNotFound:
		return kmipserver.Errorf(kmip.ResultReasonItemNotFound, "%s", msg)
	case http.StatusConflict:
		return kmipserver.Errorf(kmip.ResultReasonIllegalOperation, "%s", msg)
	case http.StatusNotImplemented:
		return kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "%s", msg)
	default:
		return kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%s", msg)
	}
}
