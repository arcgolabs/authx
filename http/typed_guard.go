package authhttp

import (
	"context"
	"reflect"

	"github.com/arcgolabs/authx"
)

// TypedCredentialResolverFunc resolves a strongly typed credential from an HTTP request.
type TypedCredentialResolverFunc[C any] func(ctx context.Context, req RequestInfo) (C, error)

// TypedAuthorizationResolverFunc builds an authorization model from a typed principal.
type TypedAuthorizationResolverFunc[P any] func(
	ctx context.Context,
	req RequestInfo,
	principal P,
) (authx.AuthorizationModel, error)

// TypedOption configures a TypedGuard.
type TypedOption[C any, P any] func(*TypedGuard[C, P])

// TypedGuard is an optional generic fast path that avoids request-path type assertions in resolvers.
type TypedGuard[C any, P any] struct {
	engine                *authx.Engine
	credentialResolver    TypedCredentialResolverFunc[C]
	authorizationResolver TypedAuthorizationResolverFunc[P]
}

// NewTypedGuard constructs a TypedGuard from engine and opts.
func NewTypedGuard[C any, P any](engine *authx.Engine, opts ...TypedOption[C, P]) *TypedGuard[C, P] {
	guard := &TypedGuard[C, P]{engine: engine}
	ApplyOptions(guard, opts...)
	return guard
}

// WithTypedCredentialResolverFunc configures the typed credential resolver.
func WithTypedCredentialResolverFunc[C any, P any](resolver TypedCredentialResolverFunc[C]) TypedOption[C, P] {
	return func(guard *TypedGuard[C, P]) {
		guard.credentialResolver = resolver
	}
}

// WithTypedAuthorizationResolverFunc configures the typed authorization resolver.
func WithTypedAuthorizationResolverFunc[C any, P any](
	resolver TypedAuthorizationResolverFunc[P],
) TypedOption[C, P] {
	return func(guard *TypedGuard[C, P]) {
		guard.authorizationResolver = resolver
	}
}

// Engine returns the underlying authx engine.
func (guard *TypedGuard[C, P]) Engine() *authx.Engine {
	if guard == nil {
		return nil
	}
	return guard.engine
}

// Check authenticates the request using the typed credential resolver.
func (guard *TypedGuard[C, P]) Check(
	ctx context.Context,
	req RequestInfo,
) (authx.AuthenticationResult, error) {
	if guard == nil || guard.engine == nil {
		return authx.AuthenticationResult{}, newRequestError("check", req, authx.ErrorCodeNilEngine, "validate typed guard engine")
	}
	if guard.credentialResolver == nil {
		return authx.AuthenticationResult{}, newRequestError("check", req, ErrorCodeCredentialResolverNotConfigured, "validate typed credential resolver")
	}

	credential, err := guard.credentialResolver(ctx, req)
	if err != nil {
		return authx.AuthenticationResult{}, wrapRequestError("resolve_credential", req, err, authx.ErrorCodeInvalidAuthenticationCredential, "resolve request credential")
	}

	result, checkErr := guard.engine.Check(ctx, credential)
	if checkErr != nil {
		return authx.AuthenticationResult{}, wrapRequestError("check", req, checkErr, authx.ErrorCodeUnauthenticated, "check request credential")
	}
	return result, nil
}

// Can authorizes the request using the typed principal.
func (guard *TypedGuard[C, P]) Can(
	ctx context.Context,
	req RequestInfo,
	principal P,
) (authx.Decision, error) {
	if guard == nil || guard.engine == nil {
		return authx.Decision{}, newRequestError("authorize", req, authx.ErrorCodeNilEngine, "validate typed guard engine")
	}
	if guard.authorizationResolver == nil {
		return authx.Decision{}, newRequestError("authorize", req, ErrorCodeAuthorizationResolverNotConfigured, "validate typed authorization resolver")
	}

	model, err := guard.authorizationResolver(ctx, req, principal)
	if err != nil {
		return authx.Decision{}, wrapRequestError("resolve_authorization", req, err, authx.ErrorCodeInvalidAuthorizationModel, "resolve authorization model")
	}

	decision, canErr := guard.engine.Can(ctx, model)
	if canErr != nil {
		return authx.Decision{}, wrapRequestError("authorize", req, canErr, authx.ErrorCodeInternal, "authorize request")
	}
	return decision, nil
}

// Require authenticates and authorizes the request.
func (guard *TypedGuard[C, P]) Require(
	ctx context.Context,
	req RequestInfo,
) (authx.AuthenticationResult, authx.Decision, error) {
	result, principal, decision, err := guard.requireTyped(ctx, req)
	if err != nil {
		return authx.AuthenticationResult{}, authx.Decision{}, err
	}
	_ = principal
	return result, decision, nil
}

// RequireTyped authenticates and authorizes the request while returning the typed principal.
func (guard *TypedGuard[C, P]) RequireTyped(
	ctx context.Context,
	req RequestInfo,
) (P, authx.Decision, error) {
	_, principal, decision, err := guard.requireTyped(ctx, req)
	return principal, decision, err
}

func (guard *TypedGuard[C, P]) requireTyped(
	ctx context.Context,
	req RequestInfo,
) (authx.AuthenticationResult, P, authx.Decision, error) {
	var zeroPrincipal P

	if err := guard.validateRequireReady(); err != nil {
		return authx.AuthenticationResult{}, zeroPrincipal, authx.Decision{}, wrapRequestError("require", req, err, authx.ErrorCodeInternal, "validate typed guard")
	}

	credential, err := guard.credentialResolver(ctx, req)
	if err != nil {
		return authx.AuthenticationResult{}, zeroPrincipal, authx.Decision{}, wrapRequestError("resolve_credential", req, err, authx.ErrorCodeInvalidAuthenticationCredential, "resolve request credential")
	}

	result, principal, err := guard.checkTyped(ctx, req, credential)
	if err != nil {
		return authx.AuthenticationResult{}, zeroPrincipal, authx.Decision{}, err
	}

	decision, err := guard.authorizeTyped(ctx, req, principal)
	if err != nil {
		return authx.AuthenticationResult{}, zeroPrincipal, authx.Decision{}, err
	}

	return result, principal, decision, nil
}

// AsGuard adapts typed guard to the classic Guard API (for middleware integrations).
func (guard *TypedGuard[C, P]) AsGuard() *Guard {
	if guard == nil {
		return nil
	}
	return NewGuard(
		guard.engine,
		WithCredentialResolverFunc(func(ctx context.Context, req RequestInfo) (any, error) {
			if guard.credentialResolver == nil {
				return nil, newRequestError("resolve_credential", req, ErrorCodeCredentialResolverNotConfigured, "validate typed credential resolver")
			}
			return guard.credentialResolver(ctx, req)
		}),
		WithAuthorizationResolverFunc(func(ctx context.Context, req RequestInfo, principal any) (authx.AuthorizationModel, error) {
			if guard.authorizationResolver == nil {
				return authx.AuthorizationModel{}, newRequestError("resolve_authorization", req, ErrorCodeAuthorizationResolverNotConfigured, "validate typed authorization resolver")
			}
			typedPrincipal, ok := principal.(P)
			if !ok {
				return authx.AuthorizationModel{}, newRequestError("resolve_authorization", req, ErrorCodePrincipalTypeMismatch, "cast principal")
			}
			return guard.authorizationResolver(ctx, req, typedPrincipal)
		}),
	)
}

func (guard *TypedGuard[C, P]) validateRequireReady() error {
	switch {
	case guard == nil || guard.engine == nil:
		return newHTTPError(authx.ErrorCodeNilEngine, "validate typed guard engine")
	case guard.credentialResolver == nil:
		return newHTTPError(ErrorCodeCredentialResolverNotConfigured, "validate typed credential resolver")
	case guard.authorizationResolver == nil:
		return newHTTPError(ErrorCodeAuthorizationResolverNotConfigured, "validate typed authorization resolver")
	default:
		return nil
	}
}

func (guard *TypedGuard[C, P]) checkTyped(
	ctx context.Context,
	req RequestInfo,
	credential C,
) (authx.AuthenticationResult, P, error) {
	var zeroPrincipal P

	result, err := guard.engine.Check(ctx, credential)
	if err != nil {
		return authx.AuthenticationResult{}, zeroPrincipal, wrapRequestError("check", req, err, authx.ErrorCodeUnauthenticated, "check request credential")
	}

	principal, principalErr := principalFromResult[P](result)
	if principalErr != nil {
		classification := ClassifyError(principalErr)
		fields := []any{
			"op", "extract_principal",
			"method", req.Method,
			"path", req.Path,
			"route_pattern", req.RoutePattern,
			"expected_principal_type", reflect.TypeFor[P](),
			"actual_principal_type", reflect.TypeOf(result.Principal),
		}
		fields = append(fields, classification.OopsFields()...)
		fields = append(fields, "http_status", StatusCodeFromClassification(classification))

		return authx.AuthenticationResult{}, zeroPrincipal, requestErrorBuilder(classification, fields...).
			Wrapf(principalErr, "extract principal from authentication result")
	}

	return result, principal, nil
}

func (guard *TypedGuard[C, P]) authorizeTyped(
	ctx context.Context,
	req RequestInfo,
	principal P,
) (authx.Decision, error) {
	model, err := guard.authorizationResolver(ctx, req, principal)
	if err != nil {
		return authx.Decision{}, wrapRequestError("resolve_authorization", req, err, authx.ErrorCodeInvalidAuthorizationModel, "resolve authorization model")
	}

	decision, err := guard.engine.Can(ctx, model)
	if err != nil {
		return authx.Decision{}, wrapRequestError("authorize", req, err, authx.ErrorCodeInternal, "authorize request")
	}

	return decision, nil
}

func principalFromResult[P any](result authx.AuthenticationResult) (P, error) {
	var zeroPrincipal P

	if result.Principal == nil {
		return zeroPrincipal, newHTTPError(ErrorCodePrincipalNotFound, "extract principal from authentication result")
	}

	principal, ok := result.Principal.(P)
	if !ok {
		return zeroPrincipal, newHTTPError(ErrorCodePrincipalTypeMismatch, "cast principal")
	}

	return principal, nil
}
