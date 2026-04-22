// Package main demonstrates using authx with the Echo adapter.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/DaiYuANg/arcgo/examples/authx/shared"
	"github.com/DaiYuANg/arcgo/logx"
	"github.com/arcgolabs/authx"
	authecho "github.com/arcgolabs/authx/http/echo"
	"github.com/labstack/echo/v4"
)

func main() {
	logger := logx.MustNew(logx.WithConsole(true), logx.WithInfoLevel()).With("example", "authx-http-echo")
	guard := shared.NewGuard()

	e := echo.New()
	e.Use(authecho.Require(guard))

	e.GET("/orders/:id", handler)
	e.DELETE("/orders/:id", handler)

	logger.Info("echo example listening", "addr", ":8082")
	logger.Info("try curl", "command", `curl -H "Authorization: Bearer admin-token" http://127.0.0.1:8082/orders/1`)
	if err := e.Start(":8082"); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func handler(c echo.Context) error {
	principal, _ := authx.PrincipalFromContextAs[authx.Principal](c.Request().Context())
	if err := c.JSON(http.StatusOK, map[string]any{
		"principal_id": principal.ID,
		"roles":        principal.Roles,
		"path":         c.Request().URL.Path,
	}); err != nil {
		return fmt.Errorf("write echo response: %w", err)
	}

	return nil
}
