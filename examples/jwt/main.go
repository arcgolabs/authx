// Package main demonstrates using authx with a JWT-backed net/http guard.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/DaiYuANg/arcgo/collectionx"
	"github.com/DaiYuANg/arcgo/examples/authx/shared"
	"github.com/DaiYuANg/arcgo/logx"
	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	authstd "github.com/arcgolabs/authx/http/std"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/go-chi/chi/v5"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

var demoJWTSecret = []byte("arcgo-demo-secret")

var (
	jwtActionResolver = shared.NewMethodActionResolver(map[string]string{
		http.MethodGet:    "query",
		http.MethodDelete: "delete",
	})
	jwtResourceResolver = shared.NewRouteResourceResolver(
		map[string]string{
			"/orders/{id}": "order",
		},
		map[string]string{
			"/orders/": "order",
		},
	)
)

func main() {
	logger := logx.MustNew(logx.WithConsole(true), logx.WithInfoLevel()).With("example", "authx-http-jwt")

	adminToken, err := issueDemoJWT("admin-1", []string{"user", "admin"}, demoJWTSecret, time.Now().Add(24*time.Hour))
	if err != nil {
		logger.Error("issue admin token failed", "error", err)
		os.Exit(1)
	}
	userToken, err := issueDemoJWT("user-1", []string{"user"}, demoJWTSecret, time.Now().Add(24*time.Hour))
	if err != nil {
		logger.Error("issue user token failed", "error", err)
		os.Exit(1)
	}

	router := chi.NewRouter()
	router.Use(authstd.Require(newJWTGuard()))

	router.Get("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		writePrincipal(w, r)
	})
	router.Delete("/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		writePrincipal(w, r)
	})

	logger.Info("jwt std example listening", "addr", ":8084")
	logger.Info("try query", "command", `curl -H "Authorization: Bearer `+userToken+`" http://127.0.0.1:8084/orders/1001`)
	logger.Info("try delete (forbidden)", "command", `curl -X DELETE -H "Authorization: Bearer `+userToken+`" http://127.0.0.1:8084/orders/1001`)
	logger.Info("try delete (allowed)", "command", `curl -X DELETE -H "Authorization: Bearer `+adminToken+`" http://127.0.0.1:8084/orders/1001`)

	server := &http.Server{
		Addr:              ":8084",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func newJWTGuard() *authhttp.Guard {
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(newJWTManager()),
		authx.WithAuthorizer(newJWTAuthorizer()),
	)

	return authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(resolveJWTCredential),
		authhttp.WithAuthorizationResolverFunc(resolveJWTAuthorization),
	)
}

func newJWTManager() *authx.ProviderManager {
	return authx.NewProviderManager(
		authjwt.NewAuthenticationProvider(authjwt.WithHMACSecret(demoJWTSecret)),
	)
}

func newJWTAuthorizer() authx.Authorizer {
	return authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		if input.Resource != "order" {
			return authx.Decision{Allowed: false, Reason: "resource_not_supported"}, nil
		}

		switch input.Action {
		case "query":
			return authx.Decision{Allowed: true}, nil
		case "delete":
			principal, ok := input.Principal.(authx.Principal)
			if !ok || !shared.HasRole(principal.Roles, "admin") {
				return authx.Decision{Allowed: false, Reason: "admin_required"}, nil
			}
			return authx.Decision{Allowed: true}, nil
		default:
			return authx.Decision{Allowed: false, Reason: "action_not_supported"}, nil
		}
	})
}

func resolveJWTCredential(_ context.Context, req authhttp.RequestInfo) (any, error) {
	token, ok := shared.ParseBearer(req.Header("Authorization"))
	if !ok {
		return nil, authx.ErrInvalidAuthenticationCredential
	}
	return authjwt.NewTokenCredential(token), nil
}

func resolveJWTAuthorization(_ context.Context, req authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
	action, err := jwtActionResolver.Resolve(req.Method)
	if err != nil {
		return authx.AuthorizationModel{}, fmt.Errorf("resolve action for method %q: %w", req.Method, err)
	}
	resource, err := jwtResourceResolver.Resolve(req.RoutePattern)
	if err != nil {
		return authx.AuthorizationModel{}, fmt.Errorf("resolve resource for route %q: %w", req.RoutePattern, err)
	}

	return authx.AuthorizationModel{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context: collectionx.NewMapFrom(map[string]any{
			"order_id":      req.PathParam("id"),
			"route_pattern": req.RoutePattern,
		}),
	}, nil
}

func issueDemoJWT(subject string, roles []string, secret []byte, expiresAt time.Time) (string, error) {
	claims := authjwt.Claims{
		Roles: roles,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwtlib.NewNumericDate(expiresAt),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
			Issuer:    "arcgo-authx-example",
		},
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign demo JWT: %w", err)
	}

	return signed, nil
}

func writePrincipal(w http.ResponseWriter, r *http.Request) {
	principal, _ := authx.PrincipalFromContextAs[authx.Principal](r.Context())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"principal_id": principal.ID,
		"roles":        principal.Roles,
		"path":         r.URL.Path,
	}); err != nil {
		slog.Error("encode JWT response failed", "error", err)
	}
}
