//go:build !no_gin

// Package main demonstrates using authx with the Gin adapter.
package main

import (
	"net/http"
	"os"

	"github.com/DaiYuANg/arcgo/examples/authx/shared"
	"github.com/DaiYuANg/arcgo/logx"
	"github.com/arcgolabs/authx"
	authgin "github.com/arcgolabs/authx/http/gin"
	"github.com/gin-gonic/gin"
)

func main() {
	logger := logx.MustNew(logx.WithConsole(true), logx.WithInfoLevel()).With("example", "authx-http-gin")
	guard := shared.NewGuard()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(authgin.Require(guard))

	router.GET("/orders/:id", handler)
	router.DELETE("/orders/:id", handler)

	logger.Info("gin example listening", "addr", ":8081")
	logger.Info("try curl", "command", `curl -H "Authorization: Bearer admin-token" http://127.0.0.1:8081/orders/1`)
	if err := router.Run(":8081"); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func handler(c *gin.Context) {
	principal, _ := authx.PrincipalFromContextAs[authx.Principal](c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"principal_id": principal.ID,
		"roles":        principal.Roles,
		"path":         c.Request.URL.Path,
	})
}
