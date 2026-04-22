package authx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hookRecorder struct {
	beforeCheck int
	afterCheck  int
	beforeCan   int
	afterCan    int
}

func (hook *hookRecorder) BeforeCheck(_ context.Context, _ any) error {
	hook.beforeCheck++
	return nil
}

func (hook *hookRecorder) AfterCheck(_ context.Context, _ any, _ authx.AuthenticationResult, _ error) {
	hook.afterCheck++
}

func (hook *hookRecorder) BeforeCan(_ context.Context, _ authx.AuthorizationModel) error {
	hook.beforeCan++
	return nil
}

func (hook *hookRecorder) AfterCan(_ context.Context, _ authx.AuthorizationModel, _ authx.Decision, _ error) {
	hook.afterCan++
}

type credentialA struct {
	ID string
}

func TestEngineCheckAndCan(t *testing.T) {
	provider := authx.NewAuthenticationProviderFunc[credentialA](func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
		return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.ID}}, nil
	})
	manager := authx.NewProviderManager(provider)

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
			principal, ok := input.Principal.(authx.Principal)
			if ok && principal.ID == "u1" && input.Action == "read" {
				return authx.Decision{Allowed: true, PolicyID: "p1"}, nil
			}
			return authx.Decision{Allowed: false, Reason: "deny"}, nil
		})),
	)

	authn, err := engine.Check(context.Background(), credentialA{ID: "u1"})
	require.NoError(t, err)
	principal, ok := authn.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "u1", principal.ID)

	decision, err := engine.Can(context.Background(), authx.AuthorizationModel{
		Principal: authn.Principal,
		Action:    "read",
		Resource:  "/orders/1",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "p1", decision.PolicyID)
}

func TestEngineCheckManagerMissing(t *testing.T) {
	engine := authx.NewEngine()
	_, err := engine.Check(context.Background(), credentialA{ID: "x"})
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrAuthenticationManagerNotConfigured)
}

func TestEngineRegisterProviderCreatesDefaultManager(t *testing.T) {
	engine := authx.NewEngine()
	err := engine.RegisterProvider(authx.NewAuthenticationProviderFunc[credentialA](
		func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.ID}}, nil
		},
	))
	require.NoError(t, err)

	result, err := engine.Check(context.Background(), credentialA{ID: "u1"})
	require.NoError(t, err)
	assert.Equal(t, authx.Principal{ID: "u1"}, result.Principal)
}

func TestRegisterProviderFunc(t *testing.T) {
	engine := authx.NewEngine()
	err := authx.RegisterProviderFunc[credentialA](
		engine,
		func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: credential.ID}, nil
		},
	)
	require.NoError(t, err)

	result, err := engine.Check(context.Background(), credentialA{ID: "u1"})
	require.NoError(t, err)
	assert.Equal(t, "u1", result.Principal)
}

func TestEngineRegisterProviderRejectsUnsupportedManager(t *testing.T) {
	engine := authx.NewEngine(authx.WithAuthenticationManager(authx.AuthenticationManagerFunc(
		func(_ context.Context, _ any) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, nil
		},
	)))

	err := engine.RegisterProvider(authx.NewAuthenticationProviderFunc[credentialA](
		func(_ context.Context, _ credentialA) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, nil
		},
	))
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrAuthenticationProviderRegistrationUnsupported)
}

func TestEngineCanAuthorizerMissing(t *testing.T) {
	provider := authx.NewAuthenticationProviderFunc[credentialA](func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
		return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.ID}}, nil
	})
	engine := authx.NewEngine(authx.WithAuthenticationManager(authx.NewProviderManager(provider)))

	_, err := engine.Can(context.Background(), authx.AuthorizationModel{
		Principal: authx.Principal{ID: "u1"},
		Action:    "read",
		Resource:  "orders",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrAuthorizerNotConfigured)
}

func TestEngineHooks(t *testing.T) {
	hook := &hookRecorder{}
	provider := authx.NewAuthenticationProviderFunc[credentialA](func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
		return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.ID}}, nil
	})
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(authx.NewProviderManager(provider)),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, _ authx.AuthorizationModel) (authx.Decision, error) {
			return authx.Decision{Allowed: true}, nil
		})),
		authx.WithHook(hook),
	)

	authn, err := engine.Check(context.Background(), credentialA{ID: "u1"})
	require.NoError(t, err)
	_, err = engine.Can(context.Background(), authx.AuthorizationModel{
		Principal: authn.Principal,
		Action:    "read",
		Resource:  "orders",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, hook.beforeCheck)
	assert.Equal(t, 1, hook.afterCheck)
	assert.Equal(t, 1, hook.beforeCan)
	assert.Equal(t, 1, hook.afterCan)
}

func TestEngineRegisterHookVariadic(t *testing.T) {
	hookA := &hookRecorder{}
	hookB := &hookRecorder{}
	provider := authx.NewAuthenticationProviderFunc[credentialA](func(_ context.Context, credential credentialA) (authx.AuthenticationResult, error) {
		return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.ID}}, nil
	})
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(authx.NewProviderManager(provider)),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, _ authx.AuthorizationModel) (authx.Decision, error) {
			return authx.Decision{Allowed: true}, nil
		})),
	)
	authx.RegisterHook(engine, hookA, nil, hookB)

	authn, err := engine.Check(context.Background(), credentialA{ID: "u1"})
	require.NoError(t, err)
	_, err = engine.Can(context.Background(), authx.AuthorizationModel{
		Principal: authn.Principal,
		Action:    "read",
		Resource:  "orders",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, hookA.beforeCheck)
	assert.Equal(t, 1, hookB.beforeCheck)
	assert.Equal(t, 1, hookA.beforeCan)
	assert.Equal(t, 1, hookB.beforeCan)
}

func TestEngineValidation(t *testing.T) {
	engine := authx.NewEngine()

	_, err := engine.Check(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrInvalidAuthenticationCredential)

	_, err = engine.Can(context.Background(), authx.AuthorizationModel{Action: "", Resource: "orders"})
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrInvalidAuthorizationModel)
}
