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
						return authx.AuthenticationResult{}, authx.NewError(
							authx.ErrorCodeInvalidAuthenticationCredential,
							"validate username/password credential",
							"op", "example_authenticate",
						)
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

Provider and resolver failures should return classified errors, usually through `authx.NewError` or `authx.WrapError`. HTTP adapters use `ClassifyError` to map those errors to safe response messages and status codes.

For fallback authentication, use `authx.NewChainAuthenticationProviderFunc` with providers for the same credential type:

```go
provider := authx.NewChainAuthenticationProviderFunc[tokenCredential](
	cacheAuthenticate,
	databaseAuthenticate,
)

manager := authx.NewProviderManager(provider)
```

The chain continues on authentication failures and returns the first successful result. Malformed credential, configuration, authorization, and internal errors stop the chain immediately.

For tenant, issuer, or key based routing, use `authx.NewKeyedSelectorAuthenticationProvider`:

```go
provider := authx.NewKeyedSelectorAuthenticationProvider(
	func(_ context.Context, credential tokenCredential) (string, error) {
		return credential.TenantID, nil
	},
	map[string]authx.TypedAuthenticationProvider[tokenCredential]{
		"tenant-a": tenantAProvider,
		"tenant-b": tenantBProvider,
	},
)
```

The JWT module includes the same pattern for multi-issuer tokens:

```go
provider := authjwt.NewIssuerAuthenticationProvider(
	map[string]authx.TypedAuthenticationProvider[authjwt.TokenCredential]{
		"issuer-a": authjwt.NewProvider(authjwt.WithIssuer("issuer-a"), authjwt.WithHMACSecret(secretA)),
		"issuer-b": authjwt.NewProvider(authjwt.WithIssuer("issuer-b"), authjwt.WithHMACSecret(secretB)),
	},
)
```

## Next

- HTTP `Guard` and the std adapter (`chi + net/http`): [HTTP integration](./http-integration)
- JWT provider module: [examples/jwt](https://github.com/arcgolabs/authx/tree/main/examples/jwt)
- Typed HTTP guard variants and framework adapters: see the [authx landing page](../) package layout
