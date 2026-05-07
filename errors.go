package authx

import (
	"errors"

	"github.com/samber/oops"
)

// ErrorCategory is a stable, transport-neutral auth failure category.
type ErrorCategory string

const (
	// ErrorCategoryNone indicates there is no error.
	ErrorCategoryNone ErrorCategory = "none"
	// ErrorCategoryAuthentication indicates credentials are missing, malformed, unknown, or rejected.
	ErrorCategoryAuthentication ErrorCategory = "authentication"
	// ErrorCategoryAuthorization indicates a principal exists, but authorization input or principal shape is invalid.
	ErrorCategoryAuthorization ErrorCategory = "authorization"
	// ErrorCategoryConfiguration indicates authx is missing required runtime wiring.
	ErrorCategoryConfiguration ErrorCategory = "configuration"
	// ErrorCategoryInternal indicates an uncategorized internal failure.
	ErrorCategoryInternal ErrorCategory = "internal"
)

const (
	// ErrorCodeNone indicates there is no error.
	ErrorCodeNone = "none"
	// ErrorCodeInvalidAuthenticationCredential indicates a nil or malformed credential.
	ErrorCodeInvalidAuthenticationCredential = "invalid_authentication_credential"
	// ErrorCodeInvalidAuthorizationModel indicates an incomplete authorization model.
	ErrorCodeInvalidAuthorizationModel = "invalid_authorization_model"
	// ErrorCodeAuthenticationProviderNotFound indicates no provider matches the credential type.
	ErrorCodeAuthenticationProviderNotFound = "authentication_provider_not_found"
	// ErrorCodeAuthenticationManagerNotConfigured indicates the engine has no auth manager.
	ErrorCodeAuthenticationManagerNotConfigured = "authentication_manager_not_configured"
	// ErrorCodeAuthenticationProviderRegistrationUnsupported indicates provider registration is unsupported.
	ErrorCodeAuthenticationProviderRegistrationUnsupported = "authentication_provider_registration_unsupported"
	// ErrorCodeAuthorizerNotConfigured indicates the engine has no authorizer.
	ErrorCodeAuthorizerNotConfigured = "authorizer_not_configured"
	// ErrorCodeNilEngine indicates an engine receiver or dependency is nil.
	ErrorCodeNilEngine = "nil_engine"
	// ErrorCodeUnauthenticated indicates authentication failed.
	ErrorCodeUnauthenticated = "unauthenticated"
	// ErrorCodeInternal indicates an uncategorized internal failure.
	ErrorCodeInternal = "internal_error"
)

var (
	// ErrInvalidAuthenticationCredential indicates that the input credential is nil or malformed.
	ErrInvalidAuthenticationCredential = errors.New("authx: invalid authentication credential")
	// ErrInvalidAuthorizationModel indicates that the authorization model is incomplete.
	ErrInvalidAuthorizationModel = errors.New("authx: invalid authorization model")
	// ErrAuthenticationProviderNotFound indicates that no provider matches the credential type.
	ErrAuthenticationProviderNotFound = errors.New("authx: authentication provider not found")
	// ErrAuthenticationManagerNotConfigured indicates that Engine has no authentication manager.
	ErrAuthenticationManagerNotConfigured = errors.New("authx: authentication manager not configured")
	// ErrAuthenticationProviderRegistrationUnsupported indicates that the configured manager cannot register providers.
	ErrAuthenticationProviderRegistrationUnsupported = errors.New("authx: authentication provider registration unsupported")
	// ErrAuthorizerNotConfigured indicates that Engine has no authorizer.
	ErrAuthorizerNotConfigured = errors.New("authx: authorizer not configured")
	// ErrNilEngine indicates that an Engine receiver or argument is nil.
	ErrNilEngine = errors.New("authx: engine is nil")
	// ErrUnauthenticated indicates that authentication failed.
	ErrUnauthenticated = errors.New("authx: unauthenticated")
)

// ErrorClassification describes a safe, stable view of an authx error.
type ErrorClassification struct {
	Category    ErrorCategory
	Code        string
	SafeMessage string
}

// OopsFields returns structured fields suitable for oops.With(...).
func (classification ErrorClassification) OopsFields() []any {
	return []any{
		"error_category", classification.Category,
		"error_code", classification.Code,
		"safe_message", classification.SafeMessage,
	}
}

// ClassifyError returns a stable category/code/message for known authx errors.
func ClassifyError(err error) ErrorClassification {
	switch {
	case err == nil:
		return ErrorClassification{
			Category:    ErrorCategoryNone,
			Code:        ErrorCodeNone,
			SafeMessage: "",
		}
	case errors.Is(err, ErrAuthenticationManagerNotConfigured):
		return configurationClassification(ErrorCodeAuthenticationManagerNotConfigured)
	case errors.Is(err, ErrAuthenticationProviderRegistrationUnsupported):
		return configurationClassification(ErrorCodeAuthenticationProviderRegistrationUnsupported)
	case errors.Is(err, ErrAuthorizerNotConfigured):
		return configurationClassification(ErrorCodeAuthorizerNotConfigured)
	case errors.Is(err, ErrNilEngine):
		return configurationClassification(ErrorCodeNilEngine)
	case errors.Is(err, ErrInvalidAuthenticationCredential):
		return authenticationClassification(ErrorCodeInvalidAuthenticationCredential)
	case errors.Is(err, ErrAuthenticationProviderNotFound):
		return authenticationClassification(ErrorCodeAuthenticationProviderNotFound)
	case errors.Is(err, ErrUnauthenticated):
		return authenticationClassification(ErrorCodeUnauthenticated)
	case errors.Is(err, ErrInvalidAuthorizationModel):
		return authorizationClassification(ErrorCodeInvalidAuthorizationModel)
	default:
		return ErrorClassification{
			Category:    ErrorCategoryInternal,
			Code:        ErrorCodeInternal,
			SafeMessage: "internal_error",
		}
	}
}

func authenticationClassification(code string) ErrorClassification {
	return ErrorClassification{
		Category:    ErrorCategoryAuthentication,
		Code:        code,
		SafeMessage: "unauthorized",
	}
}

func authorizationClassification(code string) ErrorClassification {
	return ErrorClassification{
		Category:    ErrorCategoryAuthorization,
		Code:        code,
		SafeMessage: "forbidden",
	}
}

func configurationClassification(code string) ErrorClassification {
	return ErrorClassification{
		Category:    ErrorCategoryConfiguration,
		Code:        code,
		SafeMessage: "internal_error",
	}
}

func wrapError(err error, message string, kv ...any) error {
	classification := ClassifyError(err)
	fields := append([]any{}, kv...)
	fields = append(fields, classification.OopsFields()...)
	return oops.In("authx").
		Code(classification.Code).
		With(fields...).
		Wrapf(err, "%s", message)
}
