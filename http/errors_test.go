package authhttp_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
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
		status   int
		message  string
	}{
		{
			name:     "nil",
			err:      nil,
			category: authx.ErrorCategoryNone,
			code:     authx.ErrorCodeNone,
			status:   http.StatusOK,
			message:  "",
		},
		{
			name:     "credential resolver missing",
			err:      authhttp.NewError(authhttp.ErrorCodeCredentialResolverNotConfigured, "validate credential resolver"),
			category: authx.ErrorCategoryConfiguration,
			code:     authhttp.ErrorCodeCredentialResolverNotConfigured,
			status:   http.StatusInternalServerError,
			message:  "internal_error",
		},
		{
			name:     "authentication failure",
			err:      authx.NewError(authx.ErrorCodeUnauthenticated, "authenticate"),
			category: authx.ErrorCategoryAuthentication,
			code:     authx.ErrorCodeUnauthenticated,
			status:   http.StatusUnauthorized,
			message:  "unauthorized",
		},
		{
			name:     "principal mismatch",
			err:      authhttp.NewError(authhttp.ErrorCodePrincipalTypeMismatch, "cast principal"),
			category: authx.ErrorCategoryAuthorization,
			code:     authhttp.ErrorCodePrincipalTypeMismatch,
			status:   http.StatusForbidden,
			message:  "forbidden",
		},
		{
			name:     "http code without context",
			err:      oops.In("external").Code(authhttp.ErrorCodePrincipalTypeMismatch).New("cast principal"),
			category: authx.ErrorCategoryAuthorization,
			code:     authhttp.ErrorCodePrincipalTypeMismatch,
			status:   http.StatusForbidden,
			message:  "forbidden",
		},
		{
			name:     "unknown",
			err:      errors.New("boom"),
			category: authx.ErrorCategoryInternal,
			code:     authx.ErrorCodeInternal,
			status:   http.StatusInternalServerError,
			message:  "internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authhttp.ClassifyError(tt.err)

			assert.Equal(t, tt.category, got.Category)
			assert.Equal(t, tt.code, got.Code)
			assert.Equal(t, tt.status, authhttp.StatusCodeFromError(tt.err))
			assert.Equal(t, tt.message, authhttp.ErrorMessage(tt.err))
		})
	}
}

func TestGuardWrapsRequestErrorWithOopsClassification(t *testing.T) {
	guard := authhttp.NewGuard(nil)
	_, _, err := guard.Require(context.Background(), authhttp.RequestInfo{
		Method:       http.MethodGet,
		Path:         "/orders/123",
		RoutePattern: "/orders/{id}",
	})

	require.Error(t, err)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	assert.Equal(t, authx.ErrorCodeNilEngine, oopsErr.Code())

	ctx := oopsErr.Context()
	assert.Equal(t, "require", ctx["op"])
	assert.Equal(t, http.MethodGet, ctx["method"])
	assert.Equal(t, "/orders/123", ctx["path"])
	assert.Equal(t, "/orders/{id}", ctx["route_pattern"])
	assert.Equal(t, authx.ErrorCategoryConfiguration, ctx["error_category"])
	assert.Equal(t, authx.ErrorCodeNilEngine, ctx["error_code"])
	assert.Equal(t, "internal_error", ctx["safe_message"])
	assert.Equal(t, http.StatusInternalServerError, ctx["http_status"])
}
