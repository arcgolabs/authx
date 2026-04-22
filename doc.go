// Package authx provides authentication and authorization primitives.
//
// The recommended setup is to create an Engine, register typed providers into
// the engine's default ProviderManager, and configure one Authorizer:
//
//	engine := authx.NewEngine(authx.WithAuthorizer(authorizer))
//	err := authx.RegisterProviderFunc(engine, authenticatePassword)
//	authx.RegisterHook(engine, auditHook)
//
// ProviderManager remains available when applications need to build or share an
// explicit AuthenticationManager.
package authx
