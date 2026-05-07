package authx_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		category authx.ErrorCategory
		code     string
		message  string
	}{
		{
			name:     "nil",
			err:      nil,
			category: authx.ErrorCategoryNone,
			code:     authx.ErrorCodeNone,
			message:  "",
		},
		{
			name:     "invalid credential",
			err:      fmt.Errorf("resolve credential: %w", authx.ErrInvalidAuthenticationCredential),
			category: authx.ErrorCategoryAuthentication,
			code:     authx.ErrorCodeInvalidAuthenticationCredential,
			message:  "unauthorized",
		},
		{
			name:     "unauthenticated joined",
			err:      fmt.Errorf("authenticate: %w", errors.Join(authx.ErrUnauthenticated, errors.New("provider rejected"))),
			category: authx.ErrorCategoryAuthentication,
			code:     authx.ErrorCodeUnauthenticated,
			message:  "unauthorized",
		},
		{
			name:     "invalid authorization model",
			err:      authx.ErrInvalidAuthorizationModel,
			category: authx.ErrorCategoryAuthorization,
			code:     authx.ErrorCodeInvalidAuthorizationModel,
			message:  "forbidden",
		},
		{
			name:     "configuration",
			err:      authx.ErrAuthorizerNotConfigured,
			category: authx.ErrorCategoryConfiguration,
			code:     authx.ErrorCodeAuthorizerNotConfigured,
			message:  "internal_error",
		},
		{
			name:     "unknown",
			err:      errors.New("boom"),
			category: authx.ErrorCategoryInternal,
			code:     authx.ErrorCodeInternal,
			message:  "internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authx.ClassifyError(tt.err)

			assert.Equal(t, tt.category, got.Category)
			assert.Equal(t, tt.code, got.Code)
			assert.Equal(t, tt.message, got.SafeMessage)
		})
	}
}

func TestErrorClassificationOopsFields(t *testing.T) {
	classification := authx.ErrorClassification{
		Category:    authx.ErrorCategoryAuthentication,
		Code:        authx.ErrorCodeUnauthenticated,
		SafeMessage: "unauthorized",
	}

	assert.Equal(t, []any{
		"error_category", authx.ErrorCategoryAuthentication,
		"error_code", authx.ErrorCodeUnauthenticated,
		"safe_message", "unauthorized",
	}, classification.OopsFields())
}

func TestEngineErrorsCarryOopsClassification(t *testing.T) {
	engine := authx.NewEngine()
	_, err := engine.Check(nil, nil)
	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, authx.ErrorCodeInvalidAuthenticationCredential, oopsErr.Code())

	ctx := oopsErr.Context()
	assert.Equal(t, "check", ctx["op"])
	assert.Equal(t, "validate_credential", ctx["stage"])
	assert.Equal(t, authx.ErrorCategoryAuthentication, ctx["error_category"])
	assert.Equal(t, authx.ErrorCodeInvalidAuthenticationCredential, ctx["error_code"])
	assert.Equal(t, "unauthorized", ctx["safe_message"])
}
