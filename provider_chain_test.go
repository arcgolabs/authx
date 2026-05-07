package authx_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type chainCredential struct {
	Token string
}

func TestChainAuthenticationProviderContinuesAuthenticationFailures(t *testing.T) {
	calls := 0
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential](
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{}, errors.New("cache miss")
		},
		func(_ context.Context, credential chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.Token}}, nil
		},
	)

	result, err := chain.Authenticate(context.Background(), chainCredential{Token: "user-1"})

	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	principal, ok := result.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "user-1", principal.ID)
}

func TestChainAuthenticationProviderReturnsUnifiedFailure(t *testing.T) {
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential](
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, errors.New("cache miss")
		},
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, authx.NewError(
				authx.ErrorCodeUnauthenticated,
				"remote rejected credential",
			)
		},
	)

	_, err := chain.Authenticate(context.Background(), chainCredential{Token: "missing"})

	assertAuthxErrorCode(t, err, authx.ErrorCodeUnauthenticated)
	assert.Contains(t, err.Error(), "remote rejected credential")
}

func TestChainAuthenticationProviderStopsOnMalformedCredential(t *testing.T) {
	calls := 0
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential](
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{}, authx.NewError(
				authx.ErrorCodeInvalidAuthenticationCredential,
				"validate token shape",
			)
		},
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{Principal: "should-not-run"}, nil
		},
	)

	_, err := chain.Authenticate(context.Background(), chainCredential{Token: ""})

	assertAuthxErrorCode(t, err, authx.ErrorCodeInvalidAuthenticationCredential)
	assert.Equal(t, 1, calls)
}

func TestChainAuthenticationProviderStopsOnConfigurationError(t *testing.T) {
	calls := 0
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential](
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{}, authx.NewError(
				authx.ErrorCodeAuthenticationProviderNotConfigured,
				"validate provider key source",
			)
		},
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			calls++
			return authx.AuthenticationResult{Principal: "should-not-run"}, nil
		},
	)

	_, err := chain.Authenticate(context.Background(), chainCredential{Token: "user-1"})

	assertAuthxErrorCode(t, err, authx.ErrorCodeAuthenticationProviderNotConfigured)
	assert.Equal(t, 1, calls)
}

func TestChainAuthenticationProviderRejectsEmptyChain(t *testing.T) {
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential]()

	_, err := chain.Authenticate(context.Background(), chainCredential{Token: "user-1"})

	assertAuthxErrorCode(t, err, authx.ErrorCodeAuthenticationProviderNotConfigured)
}

func TestProviderManagerUsesChainAuthenticationProvider(t *testing.T) {
	chain := authx.NewChainAuthenticationProviderFunc[chainCredential](
		func(context.Context, chainCredential) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, errors.New("primary rejected")
		},
		func(_ context.Context, credential chainCredential) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: "fallback:" + credential.Token}, nil
		},
	)
	manager := authx.NewProviderManager(chain)

	result, err := manager.Authenticate(context.Background(), chainCredential{Token: "user-1"})

	require.NoError(t, err)
	assert.Equal(t, "fallback:user-1", result.Principal)
}
