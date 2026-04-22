package authx

import "context"

type principalContextKey struct{}

// WithPrincipal stores principal in ctx for later authorization or handler use.
func WithPrincipal(ctx context.Context, principal any) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns the stored principal from ctx when present.
func PrincipalFromContext(ctx context.Context) (any, bool) {
	principal := ctx.Value(principalContextKey{})
	if principal == nil {
		return nil, false
	}
	return principal, true
}

// PrincipalFromContextAs returns the stored principal from ctx as T when possible.
func PrincipalFromContextAs[T any](ctx context.Context) (T, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(T)
	return principal, ok
}
