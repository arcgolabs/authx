package authx

import (
	"context"
	"reflect"

	"github.com/samber/oops"
)

// TypedAuthenticationProvider keeps credential strongly typed while exposing a non-generic provider surface.
type TypedAuthenticationProvider[C any] interface {
	Authenticate(ctx context.Context, credential C) (AuthenticationResult, error)
}

// TypedAuthenticationProviderFunc is a lightweight typed provider helper.
type TypedAuthenticationProviderFunc[C any] func(ctx context.Context, credential C) (AuthenticationResult, error)

// Authenticate calls fn or returns ErrUnauthenticated when fn is nil.
func (fn TypedAuthenticationProviderFunc[C]) Authenticate(
	ctx context.Context,
	credential C,
) (AuthenticationResult, error) {
	if fn == nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "validate_provider_func", "credential_type", reflect.TypeFor[C]()).
			Wrapf(ErrUnauthenticated, "authenticate provider function is nil")
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
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "validate_provider", "credential_type", credentialType).
			Wrapf(ErrUnauthenticated, "authentication provider is nil")
	}
	typedCredential, ok := credential.(C)
	if !ok {
		return AuthenticationResult{}, oops.In("authx").
			With(
				"op", "authenticate",
				"stage", "cast_credential",
				"credential_type", credentialType,
				"actual_credential_type", reflect.TypeOf(credential),
			).
			Wrapf(ErrInvalidAuthenticationCredential, "cast authentication credential")
	}
	result, err := adapter.provider.Authenticate(ctx, typedCredential)
	if err != nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "credential_type", credentialType.String()).
			Wrapf(err, "authenticate credential")
	}
	return result, nil
}

// AuthenticationManagerFunc is a lightweight manager helper.
type AuthenticationManagerFunc func(ctx context.Context, credential any) (AuthenticationResult, error)

// Authenticate calls fn or returns ErrAuthenticationManagerNotConfigured when fn is nil.
func (fn AuthenticationManagerFunc) Authenticate(
	ctx context.Context,
	credential any,
) (AuthenticationResult, error) {
	if fn == nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "authenticate", "stage", "validate_manager_func", "credential_type", reflect.TypeOf(credential)).
			Wrapf(ErrAuthenticationManagerNotConfigured, "authentication manager function is nil")
	}
	return fn(ctx, credential)
}

// AuthorizerFunc is a lightweight authorizer helper.
type AuthorizerFunc func(ctx context.Context, input AuthorizationModel) (Decision, error)

// Authorize calls fn or returns ErrAuthorizerNotConfigured when fn is nil.
func (fn AuthorizerFunc) Authorize(ctx context.Context, input AuthorizationModel) (Decision, error) {
	if fn == nil {
		return Decision{}, oops.In("authx").
			With("op", "authorize", "stage", "validate_authorizer_func", "action", input.Action, "resource", input.Resource).
			Wrapf(ErrAuthorizerNotConfigured, "authorizer function is nil")
	}
	return fn(ctx, input)
}
