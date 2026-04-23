// Package main demonstrates using authx with the Fiber adapter.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/authx/examples/shared"
	authfiber "github.com/arcgolabs/authx/http/fiber"
	"github.com/arcgolabs/logx"
	"github.com/gofiber/fiber/v2"
)

func main() {
	logger := logx.MustNew(logx.WithConsole(true), logx.WithInfoLevel()).With("example", "authx-http-fiber")
	guard := shared.NewGuard()

	app := fiber.New()
	app.Use(authfiber.Require(guard))

	app.Get("/orders/:id", handler)
	app.Delete("/orders/:id", handler)

	logger.Info("fiber example listening", "addr", ":8083")
	logger.Info("try curl", "command", `curl -H "Authorization: Bearer admin-token" http://127.0.0.1:8083/orders/1`)
	if err := app.Listen(":8083"); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func handler(c *fiber.Ctx) error {
	principal, _ := authx.PrincipalFromContextAs[authx.Principal](c.UserContext())
	if err := c.Status(http.StatusOK).JSON(fiber.Map{
		"principal_id": principal.ID,
		"roles":        principal.Roles,
		"path":         c.Path(),
	}); err != nil {
		return fmt.Errorf("write fiber response: %w", err)
	}

	return nil
}
