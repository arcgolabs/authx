package authhttp

import (
	"context"

	"github.com/arcgolabs/authx"
	"github.com/samber/oops"
)

// Option configures Guard behavior.
type Option func(*Guard)

// Guard drives authx Check/Can flow for HTTP integrations.
type Guard struct {
	engine                *authx.Engine
	credentialResolver    CredentialResolverFunc
	authorizationResolver AuthorizationResolverFunc
}

// NewGuard constructs a Guard from engine and opts.
func NewGuard(engine *authx.Engine, opts ...Option) *Guard {
	guard := &Guard{engine: engine}
	ApplyOptions(guard, opts...)
	return guard
}

// WithCredentialResolver configures how Guard reads credentials from a request.
func WithCredentialResolver(resolver CredentialResolver) Option {
	return func(guard *Guard) {
		guard.credentialResolver = toCredentialResolverFunc(resolver)
	}
}

// WithAuthorizationResolver configures how Guard builds the authorization model.
func WithAuthorizationResolver(resolver AuthorizationResolver) Option {
	return func(guard *Guard) {
		guard.authorizationResolver = toAuthorizationResolverFunc(resolver)
	}
}

// WithCredentialResolverFunc configures Guard with a function-based credential resolver.
func WithCredentialResolverFunc(resolver CredentialResolverFunc) Option {
	return func(guard *Guard) {
		guard.credentialResolver = resolver
	}
}

// WithAuthorizationResolverFunc configures Guard with a function-based authorization resolver.
func WithAuthorizationResolverFunc(resolver AuthorizationResolverFunc) Option {
	return func(guard *Guard) {
		guard.authorizationResolver = resolver
	}
}

// Engine returns the underlying authx engine.
func (guard *Guard) Engine() *authx.Engine {
	if guard == nil {
		return nil
	}
	return guard.engine
}

// Check runs engine.Check with credential resolved from request.
func (guard *Guard) Check(
	ctx context.Context,
	req RequestInfo,
) (authx.AuthenticationResult, error) {
	if guard == nil || guard.engine == nil {
		return authx.AuthenticationResult{}, wrapRequestError("check", req, ErrNilEngine, "validate guard engine")
	}
	if guard.credentialResolver == nil {
		return authx.AuthenticationResult{}, wrapRequestError("check", req, ErrCredentialResolverNotConfigured, "validate credential resolver")
	}

	credential, err := guard.credentialResolver(ctx, req)
	if err != nil {
		return authx.AuthenticationResult{}, wrapRequestError("resolve_credential", req, err, "resolve request credential")
	}

	result, err := guard.engine.Check(ctx, credential)
	if err != nil {
		return authx.AuthenticationResult{}, wrapRequestError("check", req, err, "check request credential")
	}
	return result, nil
}

// Can runs engine.Can from resolved AuthorizationModel.
func (guard *Guard) Can(
	ctx context.Context,
	req RequestInfo,
	principal any,
) (authx.Decision, error) {
	if guard == nil || guard.engine == nil {
		return authx.Decision{}, wrapRequestError("authorize", req, ErrNilEngine, "validate guard engine")
	}
	if guard.authorizationResolver == nil {
		return authx.Decision{}, wrapRequestError("authorize", req, ErrAuthorizationResolverNotConfigured, "validate authorization resolver")
	}
	if principal == nil {
		return authx.Decision{}, wrapRequestError("authorize", req, ErrPrincipalNotFound, "validate principal")
	}

	model, err := guard.authorizationResolver(ctx, req, principal)
	if err != nil {
		return authx.Decision{}, wrapRequestError("resolve_authorization", req, err, "resolve authorization model")
	}

	decision, err := guard.engine.Can(ctx, model)
	if err != nil {
		return authx.Decision{}, wrapRequestError("authorize", req, err, "authorize request")
	}
	return decision, nil
}

// Require runs Check then Can and returns both result/decision.
func (guard *Guard) Require(
	ctx context.Context,
	req RequestInfo,
) (authx.AuthenticationResult, authx.Decision, error) {
	if guard == nil || guard.engine == nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("require", req, ErrNilEngine, "validate guard engine")
	}
	if guard.credentialResolver == nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("require", req, ErrCredentialResolverNotConfigured, "validate credential resolver")
	}
	if guard.authorizationResolver == nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("require", req, ErrAuthorizationResolverNotConfigured, "validate authorization resolver")
	}

	credential, err := guard.credentialResolver(ctx, req)
	if err != nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("resolve_credential", req, err, "resolve request credential")
	}

	result, err := guard.engine.Check(ctx, credential)
	if err != nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("check", req, err, "check request credential")
	}

	if result.Principal == nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("require", req, ErrPrincipalNotFound, "extract principal from authentication result")
	}

	model, err := guard.authorizationResolver(ctx, req, result.Principal)
	if err != nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("resolve_authorization", req, err, "resolve authorization model")
	}

	decision, err := guard.engine.Can(ctx, model)
	if err != nil {
		return authx.AuthenticationResult{}, authx.Decision{}, wrapRequestError("authorize", req, err, "authorize request")
	}

	return result, decision, nil
}

func wrapRequestError(op string, req RequestInfo, err error, message string) error {
	return oops.In("authx/http").
		With("op", op, "method", req.Method, "path", req.Path, "route_pattern", req.RoutePattern).
		Wrapf(err, "%s", message)
}
