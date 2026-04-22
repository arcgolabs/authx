package authx

import "context"

// RegisterProvider appends providers to engine using the engine's provider-backed manager.
func RegisterProvider(engine *Engine, providers ...AuthenticationProvider) error {
	if engine == nil {
		return ErrNilEngine
	}
	return engine.RegisterProvider(providers...)
}

// RegisterProviderFunc wraps fn as a typed provider and registers it into engine.
func RegisterProviderFunc[C any](
	engine *Engine,
	fn func(ctx context.Context, credential C) (AuthenticationResult, error),
) error {
	return RegisterProvider(engine, NewAuthenticationProviderFunc[C](fn))
}

// RegisterHook appends hooks to engine and returns engine for fluent setup.
func RegisterHook(engine *Engine, hooks ...Hook) *Engine {
	if engine != nil {
		engine.RegisterHook(hooks...)
	}
	return engine
}
