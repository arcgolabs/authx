package authx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type selectorCredential struct {
	Tenant string
	User   string
}

func TestKeyedSelectorAuthenticationProviderSelectsProvider(t *testing.T) {
	provider := authx.NewKeyedSelectorAuthenticationProvider(
		func(_ context.Context, credential selectorCredential) (string, error) {
			return credential.Tenant, nil
		},
		map[string]authx.TypedAuthenticationProvider[selectorCredential]{
			"tenant-a": authx.TypedAuthenticationProviderFunc[selectorCredential](
				func(_ context.Context, credential selectorCredential) (authx.AuthenticationResult, error) {
					return authx.AuthenticationResult{Principal: "a:" + credential.User}, nil
				},
			),
			"tenant-b": authx.TypedAuthenticationProviderFunc[selectorCredential](
				func(_ context.Context, credential selectorCredential) (authx.AuthenticationResult, error) {
					return authx.AuthenticationResult{Principal: "b:" + credential.User}, nil
				},
			),
		},
	)

	result, err := provider.Authenticate(context.Background(), selectorCredential{
		Tenant: "tenant-b",
		User:   "alice",
	})

	require.NoError(t, err)
	assert.Equal(t, "b:alice", result.Principal)
}

func TestKeyedSelectorAuthenticationProviderReturnsProviderNotFound(t *testing.T) {
	provider := authx.NewKeyedSelectorAuthenticationProvider(
		func(_ context.Context, credential selectorCredential) (string, error) {
			return credential.Tenant, nil
		},
		map[string]authx.TypedAuthenticationProvider[selectorCredential]{},
	)

	_, err := provider.Authenticate(context.Background(), selectorCredential{Tenant: "missing"})

	assertAuthxErrorCode(t, err, authx.ErrorCodeAuthenticationProviderNotFound)
}

func TestSelectorAuthenticationProviderStopsOnSelectorError(t *testing.T) {
	provider := authx.NewSelectorAuthenticationProvider(
		func(context.Context, selectorCredential) (authx.TypedAuthenticationProvider[selectorCredential], error) {
			return nil, authx.NewError(
				authx.ErrorCodeInvalidAuthenticationCredential,
				"resolve tenant",
			)
		},
	)

	_, err := provider.Authenticate(context.Background(), selectorCredential{})

	assertAuthxErrorCode(t, err, authx.ErrorCodeInvalidAuthenticationCredential)
}

func TestKeyedSelectorAuthenticationProviderRejectsNilProvider(t *testing.T) {
	provider := authx.NewKeyedSelectorAuthenticationProvider(
		func(_ context.Context, credential selectorCredential) (string, error) {
			return credential.Tenant, nil
		},
		map[string]authx.TypedAuthenticationProvider[selectorCredential]{
			"tenant-a": nil,
		},
	)

	_, err := provider.Authenticate(context.Background(), selectorCredential{Tenant: "tenant-a"})

	assertAuthxErrorCode(t, err, authx.ErrorCodeAuthenticationProviderNotConfigured)
}

func TestProviderManagerUsesSelectorAuthenticationProvider(t *testing.T) {
	provider := authx.NewKeyedSelectorAuthenticationProvider(
		func(_ context.Context, credential selectorCredential) (string, error) {
			return credential.Tenant, nil
		},
		map[string]authx.TypedAuthenticationProvider[selectorCredential]{
			"tenant-a": authx.TypedAuthenticationProviderFunc[selectorCredential](
				func(_ context.Context, credential selectorCredential) (authx.AuthenticationResult, error) {
					return authx.AuthenticationResult{Principal: "tenant:" + credential.User}, nil
				},
			),
		},
	)
	manager := authx.NewProviderManager(provider)

	result, err := manager.Authenticate(context.Background(), selectorCredential{
		Tenant: "tenant-a",
		User:   "alice",
	})

	require.NoError(t, err)
	assert.Equal(t, "tenant:alice", result.Principal)
}
