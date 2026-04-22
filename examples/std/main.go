// Package main demonstrates using authx with the net/http adapter.
package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/DaiYuANg/arcgo/examples/authx/shared"
	"github.com/DaiYuANg/arcgo/logx"
	"github.com/arcgolabs/authx"
	authstd "github.com/arcgolabs/authx/http/std"
	"github.com/go-chi/chi/v5"
)

func main() {
	logger := logx.MustNew(logx.WithConsole(true), logx.WithInfoLevel()).With("example", "authx-http-std")
	guard := shared.NewGuard()

	router := chi.NewRouter()
	router.Use(authstd.Require(guard))

	router.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		writePrincipal(w, r)
	})
	router.Delete("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		writePrincipal(w, r)
	})

	logger.Info("std example listening", "addr", ":8080")
	logger.Info("try curl", "command", `curl -H "Authorization: Bearer admin-token" http://127.0.0.1:8080/orders/1`)
	server := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func writePrincipal(w http.ResponseWriter, r *http.Request) {
	principal, _ := authx.PrincipalFromContextAs[authx.Principal](r.Context())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"principal_id": principal.ID,
		"roles":        principal.Roles,
		"path":         r.URL.Path,
	}); err != nil {
		slog.Error("encode std response failed", "error", err)
	}
}
