package authx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrincipalHelpers(t *testing.T) {
	principal := authx.Principal{
		ID:          "u1",
		Roles:       collectionlist.NewList("user", "admin"),
		Permissions: collectionlist.NewList("orders:read", "orders:delete"),
	}

	got, ok := authx.PrincipalFromAny(&principal)
	require.True(t, ok)
	assert.Equal(t, principal, got)

	assert.True(t, authx.HasRole(principal, "admin"))
	assert.True(t, authx.HasRole(&principal, " user "))
	assert.False(t, authx.HasRole(principal, "owner"))
	assert.False(t, authx.HasRole("not-principal", "admin"))

	assert.True(t, authx.HasPermission(principal, "orders:read"))
	assert.True(t, authx.HasAnyPermission(principal, "orders:write", "orders:delete"))
	assert.False(t, authx.HasPermission(principal, "orders:write"))
	assert.False(t, authx.HasPermission((*authx.Principal)(nil), "orders:read"))
}

func TestRequireAnyRole(t *testing.T) {
	authorizer := authx.RequireAnyRole("admin", "owner")
	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: authx.Principal{
			ID:    "u1",
			Roles: collectionlist.NewList("user", "admin"),
		},
		Action:   "delete",
		Resource: "orders",
	})

	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, authx.PolicyRequireRole, decision.PolicyID)
	assert.Empty(t, decision.Reason)
}

func TestRequireAnyRoleDenied(t *testing.T) {
	authorizer := authx.RequireAnyRole("admin")
	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: authx.Principal{
			ID:    "u1",
			Roles: collectionlist.NewList("user"),
		},
		Action:   "delete",
		Resource: "orders",
	})

	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, authx.ReasonRoleRequired, decision.Reason)
	assert.Equal(t, authx.PolicyRequireRole, decision.PolicyID)
}

func TestRequirePermission(t *testing.T) {
	authorizer := authx.RequirePermission("orders:read")
	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: &authx.Principal{
			ID:          "u1",
			Permissions: collectionlist.NewList("orders:read"),
		},
		Action:   "query",
		Resource: "orders",
	})

	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, authx.PolicyRequirePermission, decision.PolicyID)
}

func TestRequirePermissionInvalidPrincipal(t *testing.T) {
	authorizer := authx.RequirePermission("orders:read")
	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "u1",
		Action:    "query",
		Resource:  "orders",
	})

	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, authx.ReasonInvalidPrincipal, decision.Reason)
	assert.Equal(t, authx.PolicyRequirePermission, decision.PolicyID)
}
