//go:build !no_echo

package echo_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authecho "github.com/arcgolabs/authx/http/echo"
	"github.com/arcgolabs/authx/http/internal/adaptertest"
	"github.com/labstack/echo/v4"
)

func TestRequireAdapterBehavior(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder func(*authhttp.Guard) echo.MiddlewareFunc
	}{
		{name: "default", builder: func(guard *authhttp.Guard) echo.MiddlewareFunc {
			return authecho.Require(guard)
		}},
		{name: "fast", builder: func(guard *authhttp.Guard) echo.MiddlewareFunc {
			return authecho.RequireFast(guard)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got adaptertest.Snapshot
			e := echo.New()
			e.Use(tc.builder(adaptertest.NewGuard(func(snapshot adaptertest.Snapshot) {
				got = snapshot
			})))
			e.GET("/orders/:id", func(c echo.Context) error {
				principal, ok := authx.PrincipalFromContextAs[authx.Principal](c.Request().Context())
				if !ok || principal.ID != adaptertest.TokenUser {
					t.Fatalf("principal missing from request context")
				}
				return c.NoContent(http.StatusNoContent)
			})

			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, adaptertest.NewRequest(http.MethodGet))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
			}
			adaptertest.AssertSnapshot(t, got, adaptertest.ExpectedSnapshot{
				Method:       http.MethodGet,
				Path:         "/orders/123",
				RoutePattern: "/orders/:id",
				PathID:       "123",
				Token:        adaptertest.TokenUser,
				Trace:        "abc",
				PrincipalID:  adaptertest.TokenUser,
			})
		})
	}
}

func TestRequireAdapterDenied(t *testing.T) {
	e := echo.New()
	e.Use(authecho.Require(adaptertest.NewGuard(nil)))
	e.DELETE("/orders/:id", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, adaptertest.NewRequest(http.MethodDelete))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	adaptertest.AssertErrorBody(t, rec.Body.String(), "no_permission")
}

func TestRequireAdapterUnauthenticated(t *testing.T) {
	e := echo.New()
	e.Use(authecho.Require(adaptertest.NewGuard(nil)))
	e.GET("/orders/:id", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	req := adaptertest.NewRequest(http.MethodGet)
	req.Header.Del(adaptertest.HeaderAuthorization)

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	adaptertest.AssertErrorBody(t, rec.Body.String(), "unauthorized")
}
