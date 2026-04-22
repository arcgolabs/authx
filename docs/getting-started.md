---
title: 'authx Getting Started'
linkTitle: 'getting-started'
description: 'Build a minimal authx Engine with Check and Can'
weight: 2
---

## Getting Started

This page walks through a **self-contained** `authx` core example: typed credential, `ProviderManager`, `Engine.Check`, and `Engine.Can`.

`authx` core does **not** ship concrete credential types (password, OTP, custom tokens). You define structs and register `AuthenticationProvider` implementations. For JWT, use the optional `github.com/arcgolabs/authx/jwt` module.

## 1) Install

```bash
go get github.com/arcgolabs/authx@latest
```

## 2) Create `main.go`

The program defines a small `usernamePassword` credential type, wires one typed provider, and a permissive authorizer for demonstration.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/arcgolabs/authx"
)

// usernamePassword is application-defined; authx stays mechanism-agnostic.
type usernamePassword struct {
	Username string
	Password string
}

func main() {
	ctx := context.Background()

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(
			authx.NewProviderManager(
				authx.NewAuthenticationProviderFunc(func(
					_ context.Context,
					in usernamePassword,
				) (authx.AuthenticationResult, error) {
					if in.Username != "alice" || in.Password != "secret" {
						return authx.AuthenticationResult{}, fmt.Errorf("invalid credentials")
					}
					return authx.AuthenticationResult{
						Principal: authx.Principal{ID: in.Username},
					}, nil
				}),
			),
		),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(
			_ context.Context,
			_ authx.AuthorizationModel,
		) (authx.Decision, error) {
			return authx.Decision{Allowed: true}, nil
		})),
	)

	result, err := engine.Check(ctx, usernamePassword{Username: "alice", Password: "secret"})
	if err != nil {
		log.Fatal(err)
	}

	decision, err := engine.Can(ctx, authx.AuthorizationModel{
		Principal: result.Principal,
		Action:    "query",
		Resource:  "order",
	})
	if err != nil {
		log.Fatal(err)
	}
	if !decision.Allowed {
		log.Fatal("authorization denied")
	}

	log.Println("ok", result.Principal)
}
```

## 3) Run

```bash
go mod init example.com/authx-minimal
go get github.com/arcgolabs/authx@latest
go run .
```

## Next

- HTTP `Guard` and the std adapter (`chi + net/http`): [HTTP integration](./http-integration)
- JWT provider module: [examples/authx/jwt](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/jwt)
- Typed HTTP guard variants and framework adapters: see the [authx landing page](../) package layout
