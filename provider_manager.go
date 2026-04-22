package authx

import (
	"context"
	"errors"
	"reflect"

	collectionmapping "github.com/DaiYuANg/arcgo/collectionx/mapping"
	"github.com/samber/oops"
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
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "validate_credential").
			Wrapf(ErrInvalidAuthenticationCredential, "validate authentication credential")
	}
	if manager == nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "validate_manager").
			Wrapf(ErrAuthenticationManagerNotConfigured, "validate authentication manager")
	}

	credentialType := reflect.TypeOf(credential)
	provider, ok := manager.providers.Get(credentialType)
	providerCount := manager.providers.Len()
	if !ok {
		return AuthenticationResult{}, oops.In("authx").
			With(
				"op", "authenticate",
				"stage", "resolve_provider",
				"credential_type", credentialType,
				"provider_count", providerCount,
			).
			Wrapf(ErrAuthenticationProviderNotFound, "resolve authentication provider")
	}

	result, err := provider.AuthenticateAny(ctx, credential)
	if err != nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "provider_authenticate", "credential_type", credentialType).
			Wrapf(errors.Join(ErrUnauthenticated, err), "authenticate credential")
	}
	return result, nil
}
