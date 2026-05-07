package authhttp

import (
	"net/http"

	"github.com/arcgolabs/authx"
	"github.com/samber/oops"
)

const (
	// ErrorCodeCredentialResolverNotConfigured indicates HTTP credential resolution is missing.
	ErrorCodeCredentialResolverNotConfigured = "http_credential_resolver_not_configured"
	// ErrorCodeAuthorizationResolverNotConfigured indicates HTTP authorization resolution is missing.
	ErrorCodeAuthorizationResolverNotConfigured = "http_authorization_resolver_not_configured"
	// ErrorCodeAccessDenied indicates an authorization decision denied the request.
	ErrorCodeAccessDenied = "http_access_denied"
	// ErrorCodePrincipalNotFound indicates authentication did not produce a principal.
	ErrorCodePrincipalNotFound = "http_principal_not_found"
	// ErrorCodePrincipalTypeMismatch indicates principal type extraction failed.
	ErrorCodePrincipalTypeMismatch = "http_principal_type_mismatch"
)

// ClassifyError returns the HTTP-aware classification for oops-classified errors.
func ClassifyError(err error) authx.ErrorClassification {
	if err == nil {
		return authx.ClassifyError(nil)
	}
	classification := authx.ClassifyError(err)
	if isHTTPErrorCode(classification.Code) {
		return ClassificationForCode(classification.Code)
	}
	return ClassificationForCode(classification.Code).Merge(classification)
}

// ClassificationForCode returns the HTTP-aware default classification for code.
func ClassificationForCode(code string) authx.ErrorClassification {
	switch code {
	case ErrorCodeCredentialResolverNotConfigured,
		ErrorCodeAuthorizationResolverNotConfigured,
		authx.ErrorCodeNilEngine:
		return httpConfigurationClassification(code)
	case ErrorCodeAccessDenied,
		ErrorCodePrincipalNotFound,
		ErrorCodePrincipalTypeMismatch:
		return httpAuthorizationClassification(code)
	default:
		return authx.ClassificationForCode(code)
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

func isHTTPErrorCode(code string) bool {
	switch code {
	case ErrorCodeCredentialResolverNotConfigured,
		ErrorCodeAuthorizationResolverNotConfigured,
		ErrorCodeAccessDenied,
		ErrorCodePrincipalNotFound,
		ErrorCodePrincipalTypeMismatch:
		return true
	default:
		return false
	}
}

func requestErrorBuilder(classification authx.ErrorClassification, fields ...any) oops.OopsErrorBuilder {
	return oops.In("authx/http").
		Code(classification.Code).
		Public(classification.SafeMessage).
		With(fields...)
}

// NewError creates an oops-classified authx/http error for code.
func NewError(code string, message string, fields ...any) error {
	return newHTTPError(code, message, fields...)
}

func newHTTPError(code string, message string, fields ...any) error {
	classification := ClassificationForCode(code)
	fields = append(fields, classification.OopsFields()...)
	fields = append(fields, "http_status", StatusCodeFromClassification(classification))
	return requestErrorBuilder(classification, fields...).New(message)
}

func errorOopsFields(err error) []any {
	classification := ClassifyError(err)
	fields := classification.OopsFields()
	fields = append(fields, "http_status", StatusCodeFromClassification(classification))
	return fields
}
