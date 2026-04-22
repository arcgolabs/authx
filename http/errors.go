package authhttp

import (
	"errors"
	"net/http"

	"github.com/arcgolabs/authx"
)

var (
	// ErrNilEngine indicates that Guard was used without an engine.
	ErrNilEngine = errors.New("authx/http: engine is nil")
	// ErrCredentialResolverNotConfigured indicates that credential resolution is missing.
	ErrCredentialResolverNotConfigured = errors.New("authx/http: credential resolver is not configured")
	// ErrAuthorizationResolverNotConfigured indicates that authorization resolution is missing.
	ErrAuthorizationResolverNotConfigured = errors.New("authx/http: authorization resolver is not configured")
	// ErrPrincipalNotFound indicates that authentication did not produce a principal.
	ErrPrincipalNotFound = errors.New("authx/http: principal not found")
	// ErrPrincipalTypeMismatch indicates that the authenticated principal does not match the expected type.
	ErrPrincipalTypeMismatch = errors.New("authx/http: principal type mismatch")
)

// StatusCodeFromError maps common auth/authz errors to HTTP status code.
func StatusCodeFromError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrCredentialResolverNotConfigured),
		errors.Is(err, ErrAuthorizationResolverNotConfigured),
		errors.Is(err, ErrNilEngine),
		errors.Is(err, authx.ErrAuthenticationManagerNotConfigured),
		errors.Is(err, authx.ErrAuthorizerNotConfigured):
		return http.StatusInternalServerError
	case errors.Is(err, authx.ErrInvalidAuthenticationCredential),
		errors.Is(err, authx.ErrAuthenticationProviderNotFound),
		errors.Is(err, authx.ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPrincipalNotFound),
		errors.Is(err, ErrPrincipalTypeMismatch),
		errors.Is(err, authx.ErrInvalidAuthorizationModel):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// ErrorMessage returns a safe default response message for auth failures.
func ErrorMessage(err error) string {
	switch StatusCodeFromError(err) {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	default:
		return "internal_error"
	}
}

// DeniedMessage returns a safe default message when Can result is denied.
func DeniedMessage(decision authx.Decision) string {
	if decision.Reason != "" {
		return decision.Reason
	}
	return "forbidden"
}
