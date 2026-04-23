package authhttp_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/arcgolabs/collectionx"
)

type testCredential struct {
	Token string
}

func newTestGuard() *authhttp.Guard {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, credential testCredential) (authx.AuthenticationResult, error) {
			if credential.Token == "" {
				return authx.AuthenticationResult{}, errors.New("empty token")
			}
			return authx.AuthenticationResult{
				Principal: authx.Principal{ID: credential.Token},
			}, nil
		}),
	)

	authorizer := authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		if input.Action == "delete" {
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
		authhttp.WithCredentialResolverFunc(func(_ context.Context, _ authhttp.RequestInfo) (any, error) {
			return testCredential{Token: "u-1"}, nil
		}),
		authhttp.WithAuthorizationResolverFunc(func(_ context.Context, req authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
			action := "query"
			if req.Method == http.MethodDelete {
				action = "delete"
			}
			return authx.AuthorizationModel{
				Principal: principal,
				Action:    action,
				Resource:  "order",
				Context: collectionx.NewMapFrom(map[string]any{
					"order_id": req.PathParam("id"),
				}),
			}, nil
		}),
	)
}

func TestGuardRequireAllowed(t *testing.T) {
	guard := newTestGuard()
	result, decision, err := guard.Require(context.Background(), authhttp.RequestInfo{
		Method:       http.MethodGet,
		Path:         "/orders/1",
		RoutePattern: "/orders/:id",
		PathParams:   map[string]string{"id": "1"},
	})
	if err != nil {
		t.Fatalf("require returned error: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed decision")
	}
	if result.Principal == nil {
		t.Fatalf("expected principal in result")
	}
}

func TestGuardRequireDenied(t *testing.T) {
	guard := newTestGuard()
	_, decision, err := guard.Require(context.Background(), authhttp.RequestInfo{
		Method:       http.MethodDelete,
		Path:         "/orders/1",
		RoutePattern: "/orders/:id",
		PathParams:   map[string]string{"id": "1"},
	})
	if err != nil {
		t.Fatalf("require returned error: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected denied decision")
	}
	if decision.Reason != "no_permission" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}
