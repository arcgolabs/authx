---
title: 'authx RBAC Integration'
linkTitle: 'rbac-integration'
description: 'Use Casbin as an authx Authorizer'
weight: 4
---

## RBAC integration

`github.com/arcgolabs/authx/rbac` adapts a Casbin enforcer to `authx.Authorizer`. Casbin remains the RBAC engine: model, policy storage, role manager, domains, and matchers stay in Casbin.

```go
authorizer := rbac.NewCasbinAuthorizer(enforcer)

engine := authx.NewEngine(
	authx.WithAuthenticationManager(manager),
	authx.WithAuthorizer(authorizer),
)
```

Default request mapping:

- subject: `authx.Principal.ID`, `*authx.Principal.ID`, string principal, or `fmt.Stringer`
- object: `AuthorizationModel.Resource`
- action: `AuthorizationModel.Action`

Use options to customize Casbin arguments:

```go
authorizer := rbac.NewCasbinAuthorizer(
	enforcer,
	rbac.WithDomainResolver(func(_ context.Context, input authx.AuthorizationModel) (string, bool, error) {
		tenantID, _ := input.Context.Get("tenant_id")
		return tenantID.(string), true, nil
	}),
)
```

Without a domain resolver, authx calls `Enforce(sub, obj, act)`. With a domain resolver, it calls `Enforce(sub, dom, obj, act)`.
