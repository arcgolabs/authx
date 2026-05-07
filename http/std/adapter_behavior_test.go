package std_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/arcgolabs/authx/http/internal/adaptertest"
	authstd "github.com/arcgolabs/authx/http/std"
	"github.com/go-chi/chi/v5"
)

func TestRequireAdapterBehavior(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder func(*authhttp.Guard) func(http.Handler) http.Handler
	}{
		{name: "default", builder: func(guard *authhttp.Guard) func(http.Handler) http.Handler {
			return authstd.Require(guard)
		}},
		{name: "fast", builder: func(guard *authhttp.Guard) func(http.Handler) http.Handler {
			return authstd.RequireFast(guard)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got adaptertest.Snapshot
			guard := adaptertest.NewGuard(func(snapshot adaptertest.Snapshot) {
				got = snapshot
			})

			router := chi.NewRouter()
			router.Use(tc.builder(guard))
			router.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
				principal, ok := authx.PrincipalFromContextAs[authx.Principal](r.Context())
				if !ok || principal.ID != adaptertest.TokenUser {
					t.Fatalf("principal missing from request context")
				}
				w.WriteHeader(http.StatusNoContent)
			})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, adaptertest.NewRequest(http.MethodGet))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
			}
			adaptertest.AssertSnapshot(t, got, adaptertest.ExpectedSnapshot{
				Method:       http.MethodGet,
				Path:         "/orders/123",
				RoutePattern: "/orders/{id}",
				PathID:       "123",
				Token:        adaptertest.TokenUser,
				Trace:        "abc",
				PrincipalID:  adaptertest.TokenUser,
			})
		})
	}
}

func TestRequireAdapterDenied(t *testing.T) {
	router := chi.NewRouter()
	router.Use(authstd.Require(adaptertest.NewGuard(nil)))
	router.Delete("/orders/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adaptertest.NewRequest(http.MethodDelete))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	adaptertest.AssertErrorBody(t, rec.Body.String(), "no_permission")
}

func TestRequireAdapterUnauthenticated(t *testing.T) {
	router := chi.NewRouter()
	router.Use(authstd.Require(adaptertest.NewGuard(nil)))
	router.Get("/orders/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := adaptertest.NewRequest(http.MethodGet)
	req.Header.Del(adaptertest.HeaderAuthorization)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	adaptertest.AssertErrorBody(t, rec.Body.String(), "unauthorized")
}
