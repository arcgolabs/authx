//go:build !no_gin

package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authgin "github.com/arcgolabs/authx/http/gin"
	"github.com/arcgolabs/authx/http/internal/adaptertest"
	"github.com/gin-gonic/gin"
)

func TestRequireAdapterBehavior(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name    string
		builder func(*authhttp.Guard) gin.HandlerFunc
	}{
		{name: "default", builder: func(guard *authhttp.Guard) gin.HandlerFunc {
			return authgin.Require(guard)
		}},
		{name: "fast", builder: func(guard *authhttp.Guard) gin.HandlerFunc {
			return authgin.RequireFast(guard)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got adaptertest.Snapshot
			router := gin.New()
			router.Use(tc.builder(adaptertest.NewGuard(func(snapshot adaptertest.Snapshot) {
				got = snapshot
			})))
			router.GET("/orders/:id", func(c *gin.Context) {
				principal, ok := authx.PrincipalFromContextAs[authx.Principal](c.Request.Context())
				if !ok || principal.ID != adaptertest.TokenUser {
					t.Fatalf("principal missing from request context")
				}
				c.Status(http.StatusNoContent)
			})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, adaptertest.NewRequest(http.MethodGet))

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
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(authgin.Require(adaptertest.NewGuard(nil)))
	router.DELETE("/orders/:id", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, adaptertest.NewRequest(http.MethodDelete))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	adaptertest.AssertErrorBody(t, rec.Body.String(), "no_permission")
}

func TestRequireAdapterUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(authgin.Require(adaptertest.NewGuard(nil)))
	router.GET("/orders/:id", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
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
