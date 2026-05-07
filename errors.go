package authx

import "github.com/samber/oops"

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
	// ErrorCodeAuthenticationProviderNotConfigured indicates a provider has no runtime implementation.
	ErrorCodeAuthenticationProviderNotConfigured = "authentication_provider_not_configured"
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

// Merge overlays non-empty fields from override onto classification.
func (classification ErrorClassification) Merge(override ErrorClassification) ErrorClassification {
	if override.Category != "" {
		classification.Category = override.Category
	}
	if override.Code != "" {
		classification.Code = override.Code
	}
	if override.SafeMessage != "" {
		classification.SafeMessage = override.SafeMessage
	}
	return classification
}

// ClassifyError returns a stable category/code/message for oops-classified errors.
func ClassifyError(err error) ErrorClassification {
	if err == nil {
		return ErrorClassification{
			Category:    ErrorCategoryNone,
			Code:        ErrorCodeNone,
			SafeMessage: "",
		}
	}
	if classification, ok := classificationFromOops(err); ok {
		return classification
	}
	return ClassificationForCode(ErrorCodeInternal)
}

// ClassificationForCode returns the default classification for a stable error code.
func ClassificationForCode(code string) ErrorClassification {
	if code == "" {
		code = ErrorCodeInternal
	}

	switch code {
	case ErrorCodeNone:
		return ErrorClassification{
			Category:    ErrorCategoryNone,
			Code:        ErrorCodeNone,
			SafeMessage: "",
		}
	case ErrorCodeAuthenticationManagerNotConfigured,
		ErrorCodeAuthenticationProviderNotConfigured,
		ErrorCodeAuthenticationProviderRegistrationUnsupported,
		ErrorCodeAuthorizerNotConfigured,
		ErrorCodeNilEngine:
		return configurationClassification(code)
	case ErrorCodeInvalidAuthenticationCredential,
		ErrorCodeAuthenticationProviderNotFound,
		ErrorCodeUnauthenticated:
		return authenticationClassification(code)
	case ErrorCodeInvalidAuthorizationModel:
		return authorizationClassification(code)
	default:
		return ErrorClassification{
			Category:    ErrorCategoryInternal,
			Code:        code,
			SafeMessage: "internal_error",
		}
	}
}

func classificationFromOops(err error) (ErrorClassification, bool) {
	oopsErr, ok := oops.AsOops(err)
	if !ok {
		return ErrorClassification{}, false
	}

	code := stringValue(oopsErr.Code())
	classification := ClassificationForCode(code)
	ctx := oopsErr.Context()
	if ctxCode := stringValue(ctx["error_code"]); code == "" && ctxCode != "" {
		classification = ClassificationForCode(ctxCode)
	}
	if category := errorCategoryValue(ctx["error_category"]); category != "" {
		classification.Category = category
	}
	if safeMessage := stringValue(ctx["safe_message"]); safeMessage != "" {
		classification.SafeMessage = safeMessage
	}
	return classification, true
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func errorCategoryValue(value any) ErrorCategory {
	switch typed := value.(type) {
	case ErrorCategory:
		return typed
	case string:
		return ErrorCategory(typed)
	default:
		return ""
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

// NewError creates an oops-classified authx error for code.
func NewError(code string, message string, kv ...any) error {
	classification := ClassificationForCode(code)
	return classifiedBuilder("authx", classification, kv...).New(message)
}

// WrapError wraps err with an oops-classified authx error.
func WrapError(err error, fallbackCode string, message string, kv ...any) error {
	if err == nil {
		return NewError(fallbackCode, message, kv...)
	}
	classification := ClassifyError(err)
	if classification.Code == ErrorCodeInternal && fallbackCode != "" {
		classification = ClassificationForCode(fallbackCode)
	}
	return classifiedBuilder("authx", classification, kv...).Wrapf(err, "%s", message)
}

func wrapError(err error, fallbackCode string, message string, kv ...any) error {
	return WrapError(err, fallbackCode, message, kv...)
}

func classifiedBuilder(domain string, classification ErrorClassification, kv ...any) oops.OopsErrorBuilder {
	fields := append([]any{}, kv...)
	fields = append(fields, classification.OopsFields()...)
	return oops.In(domain).
		Code(classification.Code).
		Public(classification.SafeMessage).
		With(fields...)
}
