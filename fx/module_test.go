package fx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	authfx "github.com/arcgolabs/authx/fx"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func TestNewAuthxModule(t *testing.T) {
	t.Parallel()

	var engine *authx.Engine

	provider := authx.NewAuthenticationProviderFunc(func(
		ctx context.Context,
		credential string,
	) (authx.AuthenticationResult, error) {
		_ = ctx
		return authx.AuthenticationResult{Principal: credential}, nil
	})

	app := fx.New(
		authfx.NewAuthxModule(
			authx.WithAuthenticationManager(authx.NewProviderManager(provider)),
		),
		fx.Populate(&engine),
	)

	require.NoError(t, app.Start(t.Context()))
	t.Cleanup(func() {
		require.NoError(t, app.Stop(context.Background()))
	})

	require.NotNil(t, engine)
	result, err := engine.Check(context.Background(), "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", result.Principal)
}

func TestWithEngineOptions(t *testing.T) {
	t.Parallel()

	var engine *authx.Engine

	provider := authx.NewAuthenticationProviderFunc(func(
		ctx context.Context,
		credential string,
	) (authx.AuthenticationResult, error) {
		_ = ctx
		return authx.AuthenticationResult{Principal: credential}, nil
	})

	app := fx.New(
		authfx.NewAuthxModule(),
		authfx.WithEngineOptions(authx.WithAuthenticationManager(authx.NewProviderManager(provider))),
		fx.Populate(&engine),
	)

	require.NoError(t, app.Start(t.Context()))
	t.Cleanup(func() {
		require.NoError(t, app.Stop(context.Background()))
	})

	require.NotNil(t, engine)
	result, err := engine.Check(context.Background(), "bob")
	require.NoError(t, err)
	require.Equal(t, "bob", result.Principal)
}
