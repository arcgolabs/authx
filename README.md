## authx

`authx` is a Go **authentication** and **authorization** abstraction for HTTP, gRPC, CLI, or any transport. The core splits concerns explicitly:

- **Authentication** — `Engine.Check(ctx, credential)` resolves identity.
- **Authorization** — `Engine.Can(ctx, AuthorizationModel)` evaluates policy for a principal and action/resource.

`authx` core is **mechanism-agnostic**: it does not embed password hashing, JWT parsing, or OTP validation. You define credential structs and register `AuthenticationProvider` implementations; use the optional `authx/jwt` module when you want the provided JWT provider.

## Current capabilities

- **`Engine`** — orchestrates `Check` / `Can` with optional hooks.
- **`ProviderManager`** — routes `Authenticate` to typed `AuthenticationProvider[C]` by credential dynamic type.
- **`authx/http`** — `Guard` resolves credentials and authorization from `RequestInfo`, then calls the engine.
- **`authx/jwt`** — optional JWT provider module, kept outside the core module because it has JWT-specific dependencies.
- **HTTP middleware** — `authx/http/std` (chi + net/http), `authx/http/gin`, `authx/http/echo`, `authx/http/fiber` integrate with common stacks.
- **Context helpers** — `WithPrincipal`, `PrincipalFromContext`, typed `PrincipalFromContextAs`.

## Package layout

- Core API: `github.com/arcgolabs/authx`
- JWT provider: `github.com/arcgolabs/authx/jwt`
- HTTP guard and `RequestInfo`: `github.com/arcgolabs/authx/http`
- std middleware (`chi + net/http`): `github.com/arcgolabs/authx/http/std`
- Gin: `github.com/arcgolabs/authx/http/gin`
- Echo: `github.com/arcgolabs/authx/http/echo`
- Fiber: `github.com/arcgolabs/authx/http/fiber`

## Documentation map

- Minimal core (`Check` / `Can`): [Getting Started](./getting-started)
- JWT provider example: [examples/authx/jwt](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/jwt)
- `Guard` + std adapter (`chi + net/http`): [HTTP integration](./http-integration)
- Release notes (v0.3.0 refactor): [authx v0.3.0](./release-v0.3.0)

## Install / Import

```bash
go get github.com/arcgolabs/authx@latest
go get github.com/arcgolabs/authx/jwt@latest
go get github.com/arcgolabs/authx/http/std@latest
go get github.com/arcgolabs/authx/http/gin@latest
go get github.com/arcgolabs/authx/http/echo@latest
go get github.com/arcgolabs/authx/http/fiber@latest
```

## Core API (summary)

| Piece | Role |
| --- | --- |
| `Engine` | Runs `Check` and `Can`, optional `Hook` |
| `ProviderManager` | Holds multiple typed `AuthenticationProvider` |
| `AuthenticationProvider[C]` | `Authenticate(ctx, C)` → `AuthenticationResult` |
| `Authorizer` | `Authorize(ctx, AuthorizationModel)` → `Decision` |
| `AuthenticationResult` | Carries `Principal` (`any`) plus optional `Details` |
| `AuthorizationModel` | `Principal`, `Action`, `Resource`, optional `Context` |
| `Decision` | `Allowed`, `Reason`, `PolicyID` |

Runnable, import-complete examples are on [Getting Started](./getting-started).

## HTTP layer (summary)

`authhttp.NewGuard` combines:

- **`WithCredentialResolverFunc`** — `(ctx, RequestInfo) → (credential any, err)`
- **`WithAuthorizationResolverFunc`** — `(ctx, RequestInfo, principal) → (AuthorizationModel, err)`

`Guard.Require` runs **Check** then **Can**. `authx/http/std` is the std adapter (`chi + net/http`) and injects `Principal` into `context` on success.

Full std adapter sample (`chi + net/http`): [HTTP integration](./http-integration).

## Error and behavior model

- `Check` returns `AuthenticationResult` and error; invalid credentials should surface as explicit errors (not silent success).
- `Can` returns `Decision` and error; policy failures should not be silently treated as deny without an observable error path where appropriate.
- HTTP middleware maps failures to stable status codes (`401` / `403`) via `authx/http` helpers; see package docs for `StatusCodeFromError`.

## Integration guide

- **httpx** — register guard middleware on route groups; keep policy evaluation in services when possible.
- **dix** — provide `Engine`, providers, and `Authorizer` from modules; inject into HTTP setup.
- **configx** — externalize secrets, provider toggles, and policy sources.
- **logx / observabilityx** — record check/can latency and error categories without logging raw secrets.

## Runnable examples (repository)

- [examples/authx/jwt](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/jwt)
- [examples/authx/std](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/std) (Chi + shared resolvers)
- [examples/authx/gin](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/gin)
- [examples/authx/echo](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/echo)
- [examples/authx/fiber](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/fiber)
- Shared helpers: [examples/authx/shared](https://github.com/DaiYuANg/arcgo/tree/main/examples/authx/shared)

## Testing and benchmarks

```bash
go test ./authx/...

# core
go test ./authx -run ^$ -bench BenchmarkEngine -benchmem

# middleware
go test ./authx/http/std -run ^$ -bench BenchmarkRequire -benchmem
go test ./authx/http/gin -run ^$ -bench BenchmarkRequire -benchmem
go test ./authx/http/echo -run ^$ -bench BenchmarkRequire -benchmem
go test ./authx/http/fiber -run ^$ -bench BenchmarkRequire -benchmem
```

## Production notes

- Keep provider behavior consistent across transports (HTTP / gRPC / CLI).
- Do not embed secrets; load via configuration.
- Treat policy loading as startup-critical and fail fast on invalid policy state.
