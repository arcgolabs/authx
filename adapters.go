package authx

import (
	"context"
	"reflect"
)

// TypedAuthenticationProvider keeps credential strongly typed while exposing a non-generic provider surface.
type TypedAuthenticationProvider[C any] interface {
	Authenticate(ctx context.Context, credential C) (AuthenticationResult, error)
}

// TypedAuthenticationProviderFunc is a lightweight typed provider helper.
type TypedAuthenticationProviderFunc[C any] func(ctx context.Context, credential C) (AuthenticationResult, error)

// Authenticate calls fn or returns an unauthenticated oops error when fn is nil.
func (fn TypedAuthenticationProviderFunc[C]) Authenticate(
	ctx context.Context,
	credential C,
) (AuthenticationResult, error) {
	if fn == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeUnauthenticated,
			"authenticate provider function is nil",
			"op", "authenticate",
			"stage", "validate_provider_func",
			"credential_type", reflect.TypeFor[C](),
		)
	}
	return fn(ctx, credential)
}

// NewAuthenticationProvider wraps a typed provider into a manager-compatible provider.
func NewAuthenticationProvider[C any](provider TypedAuthenticationProvider[C]) AuthenticationProvider {
	return &typedProviderAdapter[C]{
		provider:       provider,
		credentialType: reflect.TypeFor[C](),
	}
}

// NewAuthenticationProviderFunc wraps a typed function into a manager-compatible provider.
func NewAuthenticationProviderFunc[C any](
	fn func(ctx context.Context, credential C) (AuthenticationResult, error),
) AuthenticationProvider {
	return NewAuthenticationProvider[C](TypedAuthenticationProviderFunc[C](fn))
}

type typedProviderAdapter[C any] struct {
	provider       TypedAuthenticationProvider[C]
	credentialType reflect.Type
}

func (adapter *typedProviderAdapter[C]) CredentialType() reflect.Type {
	if adapter == nil || adapter.credentialType == nil {
		return reflect.TypeFor[C]()
	}
	return adapter.credentialType
}

func (adapter *typedProviderAdapter[C]) AuthenticateAny(
	ctx context.Context,
	credential any,
) (AuthenticationResult, error) {
	credentialType := adapter.CredentialType()
	if adapter == nil || adapter.provider == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeUnauthenticated,
			"authentication provider is nil",
			"op", "authenticate",
			"stage", "validate_provider",
			"credential_type", credentialType,
		)
	}
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
	result, err := adapter.provider.Authenticate(ctx, typedCredential)
	if err != nil {
		return AuthenticationResult{}, wrapError(
			err,
			ErrorCodeUnauthenticated,
			"authenticate credential",
			"op", "authenticate",
			"credential_type", credentialType.String(),
		)
	}
	return result, nil
}

// AuthenticationManagerFunc is a lightweight manager helper.
type AuthenticationManagerFunc func(ctx context.Context, credential any) (AuthenticationResult, error)

// Authenticate calls fn or returns a configuration oops error when fn is nil.
func (fn AuthenticationManagerFunc) Authenticate(
	ctx context.Context,
	credential any,
) (AuthenticationResult, error) {
	if fn == nil {
		return AuthenticationResult{}, NewError(
			ErrorCodeAuthenticationManagerNotConfigured,
			"authentication manager function is nil",
			"op", "authenticate",
			"stage", "validate_manager_func",
			"credential_type", reflect.TypeOf(credential),
		)
	}
	return fn(ctx, credential)
}

// AuthorizerFunc is a lightweight authorizer helper.
type AuthorizerFunc func(ctx context.Context, input AuthorizationModel) (Decision, error)

// Authorize calls fn or returns a configuration oops error when fn is nil.
func (fn AuthorizerFunc) Authorize(ctx context.Context, input AuthorizationModel) (Decision, error) {
	if fn == nil {
		return Decision{}, NewError(
			ErrorCodeAuthorizerNotConfigured,
			"authorizer function is nil",
			"op", "authorize",
			"stage", "validate_authorizer_func",
			"action", input.Action,
			"resource", input.Resource,
		)
	}
	return fn(ctx, input)
}
