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

const (
	// ErrorCodeCredentialResolverNotConfigured indicates HTTP credential resolution is missing.
	ErrorCodeCredentialResolverNotConfigured = "http_credential_resolver_not_configured"
	// ErrorCodeAuthorizationResolverNotConfigured indicates HTTP authorization resolution is missing.
	ErrorCodeAuthorizationResolverNotConfigured = "http_authorization_resolver_not_configured"
	// ErrorCodePrincipalNotFound indicates authentication did not produce a principal.
	ErrorCodePrincipalNotFound = "http_principal_not_found"
	// ErrorCodePrincipalTypeMismatch indicates principal type extraction failed.
	ErrorCodePrincipalTypeMismatch = "http_principal_type_mismatch"
)

// ClassifyError returns the HTTP-aware classification for known authx/http errors.
func ClassifyError(err error) authx.ErrorClassification {
	switch {
	case err == nil:
		return authx.ClassifyError(nil)
	case errors.Is(err, ErrCredentialResolverNotConfigured):
		return httpConfigurationClassification(ErrorCodeCredentialResolverNotConfigured)
	case errors.Is(err, ErrAuthorizationResolverNotConfigured):
		return httpConfigurationClassification(ErrorCodeAuthorizationResolverNotConfigured)
	case errors.Is(err, ErrNilEngine):
		return httpConfigurationClassification(authx.ErrorCodeNilEngine)
	case errors.Is(err, ErrPrincipalNotFound):
		return httpAuthorizationClassification(ErrorCodePrincipalNotFound)
	case errors.Is(err, ErrPrincipalTypeMismatch):
		return httpAuthorizationClassification(ErrorCodePrincipalTypeMismatch)
	default:
		return authx.ClassifyError(err)
	}
}

// StatusCodeFromError maps common auth/authz errors to HTTP status code.
func StatusCodeFromError(err error) int {
	return StatusCodeFromClassification(ClassifyError(err))
}

// StatusCodeFromClassification maps a stable classification to HTTP status.
func StatusCodeFromClassification(classification authx.ErrorClassification) int {
	switch classification.Category {
	case authx.ErrorCategoryNone:
		return http.StatusOK
	case authx.ErrorCategoryAuthentication:
		return http.StatusUnauthorized
	case authx.ErrorCategoryAuthorization:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// ErrorMessage returns a safe default response message for auth failures.
func ErrorMessage(err error) string {
	return ClassifyError(err).SafeMessage
}

// DeniedMessage returns a safe default message when Can result is denied.
func DeniedMessage(decision authx.Decision) string {
	if decision.Reason != "" {
		return decision.Reason
	}
	return "forbidden"
}

func httpConfigurationClassification(code string) authx.ErrorClassification {
	return authx.ErrorClassification{
		Category:    authx.ErrorCategoryConfiguration,
		Code:        code,
		SafeMessage: "internal_error",
	}
}

func httpAuthorizationClassification(code string) authx.ErrorClassification {
	return authx.ErrorClassification{
		Category:    authx.ErrorCategoryAuthorization,
		Code:        code,
		SafeMessage: "forbidden",
	}
}

func errorOopsFields(err error) []any {
	classification := ClassifyError(err)
	fields := classification.OopsFields()
	fields = append(fields, "http_status", StatusCodeFromClassification(classification))
	return fields
}
