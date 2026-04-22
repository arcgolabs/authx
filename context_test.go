package authx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/stretchr/testify/assert"
)

func TestPrincipalContext(t *testing.T) {
	principal := authx.Principal{ID: "u1"}
	ctx := authx.WithPrincipal(context.Background(), principal)

	got, ok := authx.PrincipalFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, principal, got)

	typed, ok := authx.PrincipalFromContextAs[authx.Principal](ctx)
	assert.True(t, ok)
	assert.Equal(t, principal, typed)
}
