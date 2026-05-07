package authx

import (
	"context"
	"reflect"
)

// ChainAuthenticationProvider tries typed providers in order for the same credential type.
type ChainAuthenticationProvider[C any] struct {
	providers      []TypedAuthenticationProvider[C]
	credentialType reflect.Type
}

// NewChainAuthenticationProvider constructs a typed provider chain.
func NewChainAuthenticationProvider[C any](
	providers ...TypedAuthenticationProvider[C],
) *ChainAuthenticationProvider[C] {
	chain := &ChainAuthenticationProvider[C]{
		credentialType: reflect.TypeFor[C](),
	}
	for _, provider := range providers {
		if provider != nil {
			chain.providers = append(chain.providers, provider)
		}
	}
	return chain
}

// NewChainAuthenticationProviderFunc constructs a typed provider chain from functions.
func NewChainAuthenticationProviderFunc[C any](
	fns ...func(context.Context, C) (AuthenticationResult, error),
) *ChainAuthenticationProvider[C] {
	providers := make([]TypedAuthenticationProvider[C], 0, len(fns))
	for _, fn := range fns {
		if fn != nil {
			providers = append(providers, TypedAuthenticationProviderFunc[C](fn))
		}
	}
	return NewChainAuthenticationProvider[C](providers...)
}

// CredentialType identifies which credential type this chain handles.
func (provider *ChainAuthenticationProvider[C]) CredentialType() reflect.Type {
	if provider == nil || provider.credentialType == nil {
		return reflect.TypeFor[C]()
	}
	return provider.credentialType
}

// AuthenticateAny casts credential and runs the typed provider chain.
func (provider *ChainAuthenticationProvider[C]) AuthenticateAny(
	ctx context.Context,
	credential any,
) (AuthenticationResult, error) {
	credentialType := provider.CredentialType()
	typedCredential, ok := credential.(C)
	if !ok {
		return AuthenticationResult{}, NewError(
			ErrorCodeInvalidAuthenticationCredential,
			"cast authentication credential",
			"op", "authenticate",
			"stage", "cast_credential",
			"credential_type", credentialType,
			"actual_credential_type", reflect.TypeOf(credential),
		)
	}
	return provider.Authenticate(ctx, typedCredential)
}

// Authenticate returns the first successful provider result.
func (provider *ChainAuthenticationProvider[C]) Authenticate(
	ctx context.Context,
	credential C,
) (AuthenticationResult, error) {
	credentialType := provider.CredentialType()
	if provider == nil || len(provider.providers) == 0 {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationProviderNotConfigured,
			"validate authentication provider chain",
			"op", "authenticate",
			"stage", "validate_provider_chain",
			"credential_type", credentialType,
		)
	}

	var lastErr error
	failedProviders := 0
	for idx, next := range provider.providers {
		result, err := next.Authenticate(ctx, credential)
		if err == nil {
			return result, nil
		}

		if !shouldContinueProviderChain(err) {
			return AuthenticationResult{}, wrapError(
				err,
				ErrorCodeInternal,
				"authenticate provider chain",
				"op", "authenticate",
				"stage", "provider_chain_authenticate",
				"credential_type", credentialType,
				"provider_index", idx,
				"provider_count", len(provider.providers),
				"failed_provider_count", failedProviders+1,
			)
		}

		lastErr = err
		failedProviders++
	}

	return AuthenticationResult{}, wrapProviderChainFailure(
		lastErr,
		credentialType,
		len(provider.providers),
		failedProviders,
	)
}

func shouldContinueProviderChain(err error) bool {
	classification, ok := classificationFromOops(err)
	if !ok {
		return true
	}
	if classification.Category != ErrorCategoryAuthentication {
		return false
	}
	return classification.Code != ErrorCodeInvalidAuthenticationCredential
}

func wrapProviderChainFailure(
	err error,
	credentialType reflect.Type,
	providerCount int,
	failedProviders int,
) error {
	fields := []any{
		"op", "authenticate",
		"stage", "provider_chain_failed",
		"credential_type", credentialType,
		"provider_count", providerCount,
		"failed_provider_count", failedProviders,
	}
	classification := ClassificationForCode(ErrorCodeUnauthenticated)
	if err == nil {
		return classifiedBuilder("authx", classification, fields...).New("authenticate provider chain")
	}
	return classifiedBuilder("authx", classification, fields...).Wrapf(err, "authenticate provider chain")
}
