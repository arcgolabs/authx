package authx

import (
	"context"
	"reflect"

	collectionmapping "github.com/arcgolabs/collectionx/mapping"
)

// ProviderManager routes authentication credential to provider by credential concrete type.
type ProviderManager struct {
	providers collectionmapping.ConcurrentMap[reflect.Type, AuthenticationProvider]
}

// NewProviderManager constructs a ProviderManager and registers providers.
func NewProviderManager(providers ...AuthenticationProvider) *ProviderManager {
	manager := &ProviderManager{}
	manager.Register(providers...)
	return manager
}

// Register adds providers keyed by their credential type.
func (manager *ProviderManager) Register(providers ...AuthenticationProvider) {
	if manager == nil || len(providers) == 0 {
		return
	}

	for _, provider := range providers {
		if provider == nil {
			continue
		}
		credentialType := provider.CredentialType()
		if credentialType == nil {
			continue
		}
		manager.providers.Set(credentialType, provider)
	}
}

// Authenticate dispatches credential to the registered provider for its concrete type.
func (manager *ProviderManager) Authenticate(
	ctx context.Context,
	credential any,
) (AuthenticationResult, error) {
	if credential == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeInvalidAuthenticationCredential,
			"validate authentication credential",
			"op", "authenticate",
			"stage", "validate_credential",
		)
	}
	if manager == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationManagerNotConfigured,
			"validate authentication manager",
			"op", "authenticate",
			"stage", "validate_manager",
		)
	}

	credentialType := reflect.TypeOf(credential)
	provider, ok := manager.providers.Get(credentialType)
	providerCount := manager.providers.Len()
	if !ok {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationProviderNotFound,
			"resolve authentication provider",
			"op", "authenticate",
			"stage", "resolve_provider",
			"credential_type", credentialType,
			"provider_count", providerCount,
		)
	}

	result, err := provider.AuthenticateAny(ctx, credential)
	if err != nil {
		return AuthenticationResult{}, wrapError(
			err,
			ErrorCodeUnauthenticated,
			"authenticate credential",
			"op", "authenticate",
			"stage", "provider_authenticate",
			"credential_type", credentialType,
		)
	}
	return result, nil
}
