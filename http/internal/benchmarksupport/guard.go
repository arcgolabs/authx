package benchmarksupport

import (
	"context"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
)

const (
	// HeaderUserID carries the benchmark user identity.
	HeaderUserID = "X-User-ID"
	// HeaderAction carries the benchmark action name.
	HeaderAction = "X-Action"
	// HeaderResource carries the benchmark resource name.
	HeaderResource = "X-Resource"
)

type credential struct {
	UserID string
}

// NewGuard constructs a benchmark-ready authhttp.Guard from dataset.
func NewGuard(dataset Dataset) *authhttp.Guard {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, input credential) (authx.AuthenticationResult, error) {
			if !dataset.HasUser(input.UserID) {
				return authx.AuthenticationResult{}, authx.ErrUnauthenticated
			}
			return authx.AuthenticationResult{
				Principal: authx.Principal{ID: input.UserID},
			}, nil
		}),
	)

	authorizer := authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		principal, ok := input.Principal.(authx.Principal)
		if !ok || principal.ID == "" {
			return authx.Decision{Allowed: false, Reason: "invalid_principal"}, nil
		}

		allowed := dataset.IsAllowed(principal.ID, input.Action, input.Resource)
		if !allowed {
			return authx.Decision{Allowed: false, Reason: "no_permission"}, nil
		}
		return authx.Decision{Allowed: true}, nil
	})

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authorizer),
	)

	return authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(resolveCredential),
		authhttp.WithAuthorizationResolverFunc(resolveAuthorization),
	)
}

func resolveCredential(_ context.Context, req authhttp.RequestInfo) (any, error) {
	userID := req.Header(HeaderUserID)
	if userID == "" {
		return nil, authx.ErrInvalidAuthenticationCredential
	}
	return credential{UserID: userID}, nil
}

func resolveAuthorization(_ context.Context, req authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
	return authx.AuthorizationModel{
		Principal: principal,
		Action:    req.Header(HeaderAction),
		Resource:  req.Header(HeaderResource),
	}, nil
}
