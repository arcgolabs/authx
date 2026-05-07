package authx

import (
	"context"
	"reflect"
)

// AuthenticationProviderSelector chooses a typed provider for credential.
type AuthenticationProviderSelector[C any] func(
	ctx context.Context,
	credential C,
) (TypedAuthenticationProvider[C], error)

// SelectorAuthenticationProvider delegates authentication to a selected typed provider.
type SelectorAuthenticationProvider[C any] struct {
	selector       AuthenticationProviderSelector[C]
	credentialType reflect.Type
}

// NewSelectorAuthenticationProvider constructs a provider selected at authentication time.
func NewSelectorAuthenticationProvider[C any](
	selector AuthenticationProviderSelector[C],
) *SelectorAuthenticationProvider[C] {
	return &SelectorAuthenticationProvider[C]{
		selector:       selector,
		credentialType: reflect.TypeFor[C](),
	}
}

// NewKeyedSelectorAuthenticationProvider selects providers by a comparable credential-derived key.
func NewKeyedSelectorAuthenticationProvider[C any, K comparable](
	selectKey func(context.Context, C) (K, error),
	providers map[K]TypedAuthenticationProvider[C],
) *SelectorAuthenticationProvider[C] {
	return NewSelectorAuthenticationProvider(func(ctx context.Context, credential C) (TypedAuthenticationProvider[C], error) {
		key, err := selectKey(ctx, credential)
		if err != nil {
			return nil, err
		}
		provider, ok := providers[key]
		if !ok {
			return nil, NewError(
				ErrorCodeAuthenticationProviderNotFound,
				"resolve authentication provider",
				"op", "authenticate",
				"stage", "select_provider",
				"provider_key", key,
				"provider_count", len(providers),
			)
		}
		if provider == nil {
			return nil, NewError(
				ErrorCodeAuthenticationProviderNotConfigured,
				"validate selected authentication provider",
				"op", "authenticate",
				"stage", "select_provider",
				"provider_key", key,
			)
		}
		return provider, nil
	})
}

// CredentialType identifies which credential type this selector handles.
func (provider *SelectorAuthenticationProvider[C]) CredentialType() reflect.Type {
	if provider == nil || provider.credentialType == nil {
		return reflect.TypeFor[C]()
	}
	return provider.credentialType
}

// AuthenticateAny casts credential and runs the selected typed provider.
func (provider *SelectorAuthenticationProvider[C]) AuthenticateAny(
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

// Authenticate delegates authentication to the selected provider.
func (provider *SelectorAuthenticationProvider[C]) Authenticate(
	ctx context.Context,
	credential C,
) (AuthenticationResult, error) {
	credentialType := provider.CredentialType()
	if provider == nil || provider.selector == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationProviderNotConfigured,
			"validate authentication provider selector",
			"op", "authenticate",
			"stage", "validate_provider_selector",
			"credential_type", credentialType,
		)
	}

	selected, err := provider.selector(ctx, credential)
	if err != nil {
		return AuthenticationResult{}, wrapError(
			err,
			ErrorCodeAuthenticationProviderNotFound,
			"select authentication provider",
			"op", "authenticate",
			"stage", "select_provider",
			"credential_type", credentialType,
		)
	}
	if selected == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationProviderNotConfigured,
			"validate selected authentication provider",
			"op", "authenticate",
			"stage", "select_provider",
			"credential_type", credentialType,
		)
	}

	result, err := selected.Authenticate(ctx, credential)
	if err != nil {
		return AuthenticationResult{}, wrapError(
			err,
			ErrorCodeUnauthenticated,
			"authenticate selected provider",
			"op", "authenticate",
			"stage", "selected_provider_authenticate",
			"credential_type", credentialType,
			"provider_type", reflect.TypeOf(selected),
		)
	}
	return result, nil
}
