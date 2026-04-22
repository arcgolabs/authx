package std_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DaiYuANg/arcgo/collectionx"
	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authstd "github.com/arcgolabs/authx/http/std"
	"github.com/go-chi/chi/v5"
)

type middlewareCredential struct {
	Token string
}

func newMiddlewareGuard() *authhttp.Guard {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, credential middlewareCredential) (authx.AuthenticationResult, error) {
			if credential.Token == "" {
				return authx.AuthenticationResult{}, errors.New("missing token")
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
		authhttp.WithCredentialResolverFunc(func(_ context.Context, req authhttp.RequestInfo) (any, error) {
			return middlewareCredential{Token: req.Header("Authorization")}, nil
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

func TestRequireAllowed(t *testing.T) {
	guard := newMiddlewareGuard()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authx.PrincipalFromContext(r.Context()); !ok {
			t.Fatalf("principal missing in request context")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	handler := authstd.Require(guard)(next)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/123", http.NoBody)
	req.Header.Set("Authorization", "user-1")
	req = req.WithContext(authhttp.WithPathParams(authhttp.WithRoutePattern(req.Context(), "/orders/:id"), map[string]string{"id": "123"}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestRequireDenied(t *testing.T) {
	guard := newMiddlewareGuard()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := authstd.Require(guard)(next)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/orders/123", http.NoBody)
	req.Header.Set("Authorization", "user-1")
	req = req.WithContext(authhttp.WithPathParams(authhttp.WithRoutePattern(req.Context(), "/orders/:id"), map[string]string{"id": "123"}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestRequireUsesCHIRouteMetadataByDefault(t *testing.T) {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, credential middlewareCredential) (authx.AuthenticationResult, error) {
			if credential.Token == "" {
				return authx.AuthenticationResult{}, errors.New("missing token")
			}
			return authx.AuthenticationResult{Principal: authx.Principal{ID: credential.Token}}, nil
		}),
	)

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
			if input.Action == "/orders/{id}" && input.Resource == "123" {
				return authx.Decision{Allowed: true}, nil
			}
			return authx.Decision{Allowed: false, Reason: "missing_route_metadata"}, nil
		})),
	)

	guard := authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(func(_ context.Context, req authhttp.RequestInfo) (any, error) {
			return middlewareCredential{Token: req.Header("Authorization")}, nil
		}),
		authhttp.WithAuthorizationResolverFunc(func(_ context.Context, req authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
			return authx.AuthorizationModel{
				Principal: principal,
				Action:    req.RoutePattern,
				Resource:  req.PathParam("id"),
				Context:   collectionx.NewMapFrom(map[string]any{"path": req.Path}),
			}, nil
		}),
	)

	router := chi.NewRouter()
	router.Use(authstd.Require(guard))
	router.Get("/orders/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/123", http.NoBody)
	req.Header.Set("Authorization", "user-1")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}
