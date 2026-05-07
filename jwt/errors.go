package authjwt

import (
	"github.com/arcgolabs/authx"
	"github.com/samber/oops"
)

const (
	// ErrorCodeTokenEmpty indicates that the JWT credential did not contain a token string.
	ErrorCodeTokenEmpty = "jwt_token_empty"
	// ErrorCodeKeyfuncNotConfigured indicates that a provider has no verification key function.
	ErrorCodeKeyfuncNotConfigured = "jwt_keyfunc_not_configured"
	// ErrorCodeInvalidToken indicates that JWT parsing or validation failed.
	ErrorCodeInvalidToken = "jwt_invalid_token"
	// ErrorCodeSubjectRequired indicates that default principal mapping could not find a subject.
	ErrorCodeSubjectRequired = "jwt_subject_required"
)

// ClassifyError returns the JWT-aware classification for oops-classified errors.
func ClassifyError(err error) authx.ErrorClassification {
	if err == nil {
		return authx.ClassifyError(nil)
	}
	classification := authx.ClassifyError(err)
	if isJWTErrorCode(classification.Code) {
		return ClassificationForCode(classification.Code)
	}
	return ClassificationForCode(classification.Code).Merge(classification)
}

// ClassificationForCode returns the JWT-aware default classification for code.
func ClassificationForCode(code string) authx.ErrorClassification {
	switch code {
	case ErrorCodeKeyfuncNotConfigured:
		return authx.ErrorClassification{
			Category:    authx.ErrorCategoryConfiguration,
			Code:        code,
			SafeMessage: "internal_error",
		}
	case ErrorCodeTokenEmpty,
		ErrorCodeInvalidToken,
		ErrorCodeSubjectRequired:
		return authx.ErrorClassification{
			Category:    authx.ErrorCategoryAuthentication,
			Code:        code,
			SafeMessage: "unauthorized",
		}
	default:
		return authx.ClassificationForCode(code)
	}
}

func isJWTErrorCode(code string) bool {
	switch code {
	case ErrorCodeTokenEmpty,
		ErrorCodeKeyfuncNotConfigured,
		ErrorCodeInvalidToken,
		ErrorCodeSubjectRequired:
		return true
	default:
		return false
	}
}

// NewError creates an oops-classified authx/jwt error for code.
func NewError(code string, message string, fields ...any) error {
	classification := ClassificationForCode(code)
	return errorBuilder(classification, fields...).New(message)
}

// WrapError wraps err with an oops-classified authx/jwt error.
func WrapError(err error, fallbackCode string, message string, fields ...any) error {
	if err == nil {
		return NewError(fallbackCode, message, fields...)
	}
	classification := ClassifyError(err)
	if classification.Code == authx.ErrorCodeInternal && fallbackCode != "" {
		classification = ClassificationForCode(fallbackCode)
	}
	return errorBuilder(classification, fields...).Wrapf(err, "%s", message)
}

func newError(code string, message string, fields ...any) error {
	return NewError(code, message, fields...)
}

func wrapError(err error, fallbackCode string, message string, fields ...any) error {
	return WrapError(err, fallbackCode, message, fields...)
}

func errorBuilder(classification authx.ErrorClassification, fields ...any) oops.OopsErrorBuilder {
	fields = append(fields, "provider", "jwt")
	fields = append(fields, classification.OopsFields()...)
	return oops.In("authx/jwt").
		Code(classification.Code).
		Public(classification.SafeMessage).
		With(fields...)
}
