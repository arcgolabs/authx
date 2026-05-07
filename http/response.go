package authhttp

import "github.com/arcgolabs/authx"

// ErrorResponse is the transport-safe auth failure payload model.
type ErrorResponse struct {
	Error    string              `json:"error"`
	Code     string              `json:"code,omitempty"`
	Category authx.ErrorCategory `json:"category,omitempty"`
	Status   int                 `json:"status,omitempty"`
}

// ErrorResponseFromError builds a safe response from an auth error.
func ErrorResponseFromError(err error) ErrorResponse {
	classification := ClassifyError(err)
	return ErrorResponseFromClassification(classification, classification.SafeMessage)
}

// ErrorResponseFromCode builds a safe response from a stable error code.
func ErrorResponseFromCode(code string) ErrorResponse {
	classification := ClassificationForCode(code)
	return ErrorResponseFromClassification(classification, classification.SafeMessage)
}

// ErrorResponseFromDecision builds a safe response for an explicit authorization denial.
func ErrorResponseFromDecision(decision authx.Decision) ErrorResponse {
	return ErrorResponseFromClassification(
		ClassificationForCode(ErrorCodeAccessDenied),
		DeniedMessage(decision),
	)
}

// ErrorResponseFromClassification builds a safe response from a classification and message.
func ErrorResponseFromClassification(classification authx.ErrorClassification, message string) ErrorResponse {
	if message == "" {
		message = classification.SafeMessage
	}
	code := classification.Code
	if code == authx.ErrorCodeNone {
		code = ""
	}
	category := classification.Category
	if category == authx.ErrorCategoryNone {
		category = ""
	}
	return ErrorResponse{
		Error:    message,
		Code:     code,
		Category: category,
		Status:   StatusCodeFromClassification(classification),
	}
}
