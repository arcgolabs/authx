package authhttp

import (
	"context"

	"github.com/arcgolabs/authx"
	"github.com/samber/mo"
)

// CredentialResolver resolves auth credential from HTTP request shape.
type CredentialResolver interface {
	ResolveCredential(ctx context.Context, req RequestInfo) (any, error)
}

// AuthorizationResolver resolves AuthorizationModel from HTTP request + principal.
type AuthorizationResolver interface {
	ResolveAuthorization(ctx context.Context, req RequestInfo, principal any) (authx.AuthorizationModel, error)
}

// CredentialResolverFunc is function adapter for CredentialResolver.
type CredentialResolverFunc func(ctx context.Context, req RequestInfo) (any, error)

// ResolveCredential calls fn.
func (fn CredentialResolverFunc) ResolveCredential(ctx context.Context, req RequestInfo) (any, error) {
	return fn(ctx, req)
}

func toCredentialResolverFunc(resolver CredentialResolver) CredentialResolverFunc {
	resolverValue, ok := mo.TupleToOption(resolver, resolver != nil).Get()
	if !ok {
		return nil
	}
	if fn, ok := resolverValue.(CredentialResolverFunc); ok {
		return fn
	}
	return func(ctx context.Context, req RequestInfo) (any, error) {
		return resolverValue.ResolveCredential(ctx, req)
	}
}

// AuthorizationResolverFunc is function adapter for AuthorizationResolver.
type AuthorizationResolverFunc func(
	ctx context.Context,
	req RequestInfo,
	principal any,
) (authx.AuthorizationModel, error)

// ResolveAuthorization calls fn.
func (fn AuthorizationResolverFunc) ResolveAuthorization(
	ctx context.Context,
	req RequestInfo,
	principal any,
) (authx.AuthorizationModel, error) {
	return fn(ctx, req, principal)
}

func toAuthorizationResolverFunc(resolver AuthorizationResolver) AuthorizationResolverFunc {
	resolverValue, ok := mo.TupleToOption(resolver, resolver != nil).Get()
	if !ok {
		return nil
	}
	if fn, ok := resolverValue.(AuthorizationResolverFunc); ok {
		return fn
	}
	return func(ctx context.Context, req RequestInfo, principal any) (authx.AuthorizationModel, error) {
		return resolverValue.ResolveAuthorization(ctx, req, principal)
	}
}
