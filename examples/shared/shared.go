package shared

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/arcgolabs/collectionx"
)

// BearerCredential carries the bearer token resolved from a request.
type BearerCredential struct {
	Token string
}

var (
	defaultActionResolver = NewMethodActionResolver(map[string]string{
		http.MethodGet:    "query",
		http.MethodDelete: "delete",
	})
	defaultResourceResolver = NewRouteResourceResolver(
		map[string]string{
			"/orders/:id":  "order",
			"/orders/{id}": "order",
		},
		map[string]string{
			"/orders/": "order",
		},
	)
)

// NewGuard builds the shared demo guard used by the authx HTTP examples.
func NewGuard() *authhttp.Guard {
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(newManager()),
		authx.WithAuthorizer(newAuthorizer()),
	)

	return authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(resolveCredential),
		authhttp.WithAuthorizationResolverFunc(resolveAuthorization),
	)
}

func newManager() *authx.ProviderManager {
	return authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(
			func(_ context.Context, credential BearerCredential) (authx.AuthenticationResult, error) {
				token := strings.TrimSpace(credential.Token)
				if token == "" {
					return authx.AuthenticationResult{}, authx.ErrInvalidAuthenticationCredential
				}

				roles := collectionx.NewList("user")
				if token == "admin-token" {
					roles.Add("admin")
				}

				return authx.AuthenticationResult{
					Principal: authx.Principal{
						ID:    token,
						Roles: roles,
					},
				}, nil
			},
		),
	)
}

func newAuthorizer() authx.Authorizer {
	return authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		if input.Resource != "order" {
			return authx.Decision{Allowed: false, Reason: "resource_not_supported"}, nil
		}

		switch input.Action {
		case "query":
			return authx.Decision{Allowed: true}, nil
		case "delete":
			principal, ok := input.Principal.(authx.Principal)
			if !ok {
				return authx.Decision{Allowed: false, Reason: "invalid_principal"}, nil
			}
			if HasRole(principal.Roles, "admin") {
				return authx.Decision{Allowed: true}, nil
			}
			return authx.Decision{Allowed: false, Reason: "admin_required"}, nil
		default:
			return authx.Decision{Allowed: false, Reason: "action_not_supported"}, nil
		}
	})
}

func resolveCredential(_ context.Context, req authhttp.RequestInfo) (any, error) {
	token, ok := ParseBearer(req.Header("Authorization"))
	if !ok {
		return nil, fmt.Errorf("%w: missing bearer token", authx.ErrInvalidAuthenticationCredential)
	}
	return BearerCredential{Token: token}, nil
}

func resolveAuthorization(
	_ context.Context,
	req authhttp.RequestInfo,
	principal any,
) (authx.AuthorizationModel, error) {
	action, err := defaultActionResolver.Resolve(req.Method)
	if err != nil {
		return authx.AuthorizationModel{}, err
	}
	resource, err := defaultResourceResolver.Resolve(req.RoutePattern)
	if err != nil {
		return authx.AuthorizationModel{}, err
	}

	return authx.AuthorizationModel{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context: collectionx.NewMapFrom(map[string]any{
			"route_pattern": req.RoutePattern,
			"order_id":      req.PathParam("id"),
		}),
	}, nil
}
