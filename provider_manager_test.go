package authx_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type usernamePasswordCredential struct {
	username string
	passcode string
}

type phoneOTPCredential struct {
	phone string
	code  string
}

func TestProviderManagerRoutesMultipleTypedProviders(t *testing.T) {
	passwordProvider := authx.NewAuthenticationProviderFunc[usernamePasswordCredential](
		func(_ context.Context, credential usernamePasswordCredential) (authx.AuthenticationResult, error) {
			if credential.username == "alice" && credential.passcode == "secret" {
				return authx.AuthenticationResult{Principal: authx.Principal{ID: "alice"}}, nil
			}
			return authx.AuthenticationResult{}, errors.New("bad credentials")
		},
	)

	phoneProvider := authx.NewAuthenticationProviderFunc[phoneOTPCredential](
		func(_ context.Context, credential phoneOTPCredential) (authx.AuthenticationResult, error) {
			if credential.phone == "13800000000" && credential.code == "123456" {
				return authx.AuthenticationResult{Principal: authx.Principal{ID: "phone-user"}}, nil
			}
			return authx.AuthenticationResult{}, errors.New("bad otp")
		},
	)

	manager := authx.NewProviderManager(passwordProvider, phoneProvider)

	res1, err := manager.Authenticate(context.Background(), usernamePasswordCredential{username: "alice", passcode: "secret"})
	require.NoError(t, err)
	principal1, ok := res1.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "alice", principal1.ID)

	res2, err := manager.Authenticate(context.Background(), phoneOTPCredential{phone: "13800000000", code: "123456"})
	require.NoError(t, err)
	principal2, ok := res2.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "phone-user", principal2.ID)
}

func TestProviderManagerProviderNotFound(t *testing.T) {
	manager := authx.NewProviderManager()
	_, err := manager.Authenticate(context.Background(), struct{ Value string }{Value: "x"})
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrAuthenticationProviderNotFound)
}

func TestProviderManagerVariadicRegister(t *testing.T) {
	providerA := authx.NewAuthenticationProviderFunc[string](
		func(_ context.Context, credential string) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: "A:" + credential}, nil
		},
	)
	providerB := authx.NewAuthenticationProviderFunc[int](
		func(_ context.Context, credential int) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: credential + 1}, nil
		},
	)

	manager := authx.NewProviderManager()
	manager.Register(providerA, providerB)

	res, err := manager.Authenticate(context.Background(), 41)
	require.NoError(t, err)
	assert.Equal(t, 42, res.Principal)
}

func TestProviderManagerZeroValueRegister(t *testing.T) {
	provider := authx.NewAuthenticationProviderFunc[string](
		func(_ context.Context, credential string) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: "user:" + credential}, nil
		},
	)

	var manager authx.ProviderManager
	manager.Register(provider)

	res, err := manager.Authenticate(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "user:alice", res.Principal)
}

func TestProviderManagerRejectsNilCredential(t *testing.T) {
	manager := authx.NewProviderManager()
	_, err := manager.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrInvalidAuthenticationCredential)
}

func TestProviderManagerRejectsNilTypedProvider(t *testing.T) {
	manager := authx.NewProviderManager(authx.NewAuthenticationProvider[string](nil))

	_, err := manager.Authenticate(context.Background(), "alice")
	require.Error(t, err)
	assert.ErrorIs(t, err, authx.ErrUnauthenticated)
}
