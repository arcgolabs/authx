---
title: 'authx HTTP Integration'
linkTitle: 'http-integration'
description: 'Use authx/http Guard with the std (chi + net/http) middleware'
weight: 3
---

## HTTP integration

`github.com/arcgolabs/authx/http` exposes a **Guard** that runs `Engine.Check` and `Engine.Can` using HTTP-normalized `RequestInfo`. Package `github.com/arcgolabs/authx/http/std` is the repo's **std adapter**, meaning **chi + net/http** (`Require` / `RequireFast`).

This matches `httpx/adapter/std`: `std` means `chi` is the default router semantics, while the handler type stays `net/http`.

## 1) Install

```bash
go get github.com/arcgolabs/authx@latest
go get github.com/arcgolabs/authx/http/std@latest
```

## 2) Create `main.go`

The server:

- Resolves a `bearerCredential` from the `Authorization` header (`Bearer <token>`).
- Maps the authenticated principal to an `AuthorizationModel` (action/resource).
- Protects `/hello` with `std.Require(guard)`.
- Reads `authx.Principal` from request context in the handler.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/arcgolabs/authx/http/std"
	"github.com/go-chi/chi/v5"
)

type bearerCredential struct {
	Token string
}

func main() {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, c bearerCredential) (authx.AuthenticationResult, error) {
			if c.Token != "secret-token" {
				return authx.AuthenticationResult{}, fmt.Errorf("invalid token")
			}
			return authx.AuthenticationResult{
				Principal: authx.Principal{ID: "alice"},
			}, nil
		}),
	)

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, _ authx.AuthorizationModel) (authx.Decision, error) {
			return authx.Decision{Allowed: true}, nil
		})),
	)

	guard := authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(func(_ context.Context, req authhttp.RequestInfo) (any, error) {
			raw := strings.TrimSpace(req.Header("Authorization"))
			token := strings.TrimPrefix(raw, "Bearer ")
			token = strings.TrimSpace(token)
			return bearerCredential{Token: token}, nil
		}),
		authhttp.WithAuthorizationResolverFunc(func(_ context.Context, _ authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
			return authx.AuthorizationModel{
				Principal: principal,
				Action:    "read",
				Resource:  "profile",
			}, nil
		}),
	)

	router := chi.NewRouter()
	router.Use(std.Require(guard))
	router.Get("/hello", hello)

	log.Fatal(http.ListenAndServe(":8080", router))
}

func hello(w http.ResponseWriter, r *http.Request) {
	p, ok := authx.PrincipalFromContextAs[authx.Principal](r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "hello %s\n", p.ID)
}
```

## 3) Run and try

```bash
go mod init example.com/authx-http
go get github.com/arcgolabs/authx@latest
go get github.com/arcgolabs/authx/http/std@latest
go run .
```

```bash
curl -i -H "Authorization: Bearer secret-token" http://127.0.0.1:8080/hello
```

## Related

- Core `Engine` only: [Getting Started](./getting-started)
- Gin / Echo / Fiber adapters: see package layout on the [authx landing page](../)
- Runnable demos with routers: [examples/authx/std](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/std) and sibling folders under `examples/authx/`
