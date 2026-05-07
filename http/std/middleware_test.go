package std_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authstd "github.com/arcgolabs/authx/http/std"
	collectionmapping "github.com/arcgolabs/collectionx/mapping"
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
				Context: collectionmapping.NewMapFrom(map[string]any{
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

func TestRequireUsesErrorResponseWriter(t *testing.T) {
	handler := authstd.Require(
		newMiddlewareGuard(),
		authstd.WithErrorResponseWriter(func(w http.ResponseWriter, _ *http.Request, response authhttp.ErrorResponse) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(response.Status)
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/123", http.NoBody)
	req = req.WithContext(authhttp.WithPathParams(authhttp.WithRoutePattern(req.Context(), "/orders/:id"), map[string]string{"id": "123"}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	var payload authhttp.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "unauthorized" {
		t.Fatalf("expected safe error message, got %q", payload.Error)
	}
	if payload.Code != authx.ErrorCodeUnauthenticated {
		t.Fatalf("expected code %q, got %q", authx.ErrorCodeUnauthenticated, payload.Code)
	}
	if payload.Category != authx.ErrorCategoryAuthentication {
		t.Fatalf("expected category %q, got %q", authx.ErrorCategoryAuthentication, payload.Category)
	}
	if payload.Status != http.StatusUnauthorized {
		t.Fatalf("expected payload status %d, got %d", http.StatusUnauthorized, payload.Status)
	}
}

func TestRequireKeepsFailureHandlerCompatibility(t *testing.T) {
	var gotStatus int
	var gotMessage string

	handler := authstd.Require(
		newMiddlewareGuard(),
		authstd.WithFailureHandler(func(w http.ResponseWriter, _ *http.Request, status int, message string) {
			gotStatus = status
			gotMessage = message
			w.WriteHeader(status)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/orders/123", http.NoBody)
	req = req.WithContext(authhttp.WithPathParams(authhttp.WithRoutePattern(req.Context(), "/orders/:id"), map[string]string{"id": "123"}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if gotStatus != http.StatusUnauthorized {
		t.Fatalf("expected handler status %d, got %d", http.StatusUnauthorized, gotStatus)
	}
	if gotMessage != "unauthorized" {
		t.Fatalf("expected handler message %q, got %q", "unauthorized", gotMessage)
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
				Context:   collectionmapping.NewMapFrom(map[string]any{"path": req.Path}),
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
