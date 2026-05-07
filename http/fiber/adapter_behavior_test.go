//go:build !no_fiber

package fiber_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authfiber "github.com/arcgolabs/authx/http/fiber"
	"github.com/arcgolabs/authx/http/internal/adaptertest"
	"github.com/gofiber/fiber/v2"
)

func TestRequireAdapterBehavior(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder func(*authhttp.Guard) fiber.Handler
	}{
		{name: "default", builder: func(guard *authhttp.Guard) fiber.Handler {
			return authfiber.Require(guard)
		}},
		{name: "fast", builder: func(guard *authhttp.Guard) fiber.Handler {
			return authfiber.RequireFast(guard)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got adaptertest.Snapshot
			app := fiber.New(fiber.Config{DisableStartupMessage: true})
			app.Use(tc.builder(adaptertest.NewGuard(func(snapshot adaptertest.Snapshot) {
				got = snapshot
			})))
			app.Get("/orders/:id", func(c *fiber.Ctx) error {
				principal, ok := authx.PrincipalFromContextAs[authx.Principal](c.UserContext())
				if !ok || principal.ID != adaptertest.TokenUser {
					t.Fatalf("principal missing from user context")
				}
				return c.SendStatus(http.StatusNoContent)
			})

			resp := performFiberRequest(t, app, adaptertest.NewRequest(http.MethodGet))

			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
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
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(authfiber.Require(adaptertest.NewGuard(nil)))
	app.Delete("/orders/:id", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	resp := performFiberRequest(t, app, adaptertest.NewRequest(http.MethodDelete))
	body := readResponseBody(t, resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
	adaptertest.AssertErrorBody(t, body, "no_permission")
}

func TestRequireAdapterUnauthenticated(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(authfiber.Require(adaptertest.NewGuard(nil)))
	app.Get("/orders/:id", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := adaptertest.NewRequest(http.MethodGet)
	req.Header.Del(adaptertest.HeaderAuthorization)

	resp := performFiberRequest(t, app, req)
	body := readResponseBody(t, resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
	adaptertest.AssertErrorBody(t, body, "unauthorized")
}

func performFiberRequest(t *testing.T, app *fiber.App, req *http.Request) *http.Response {
	t.Helper()

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response body: %v", err)
		}
	})
	return resp
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}
