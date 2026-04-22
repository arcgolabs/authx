package authx

import "log/slog"

// EngineOption configures Engine construction.
type EngineOption func(*Engine)

// WithAuthenticationManager configures the authentication manager used by Engine.
func WithAuthenticationManager(manager AuthenticationManager) EngineOption {
	return func(engine *Engine) {
		engine.SetAuthenticationManager(manager)
	}
}

// WithAuthorizer configures the authorizer used by Engine.
func WithAuthorizer(authorizer Authorizer) EngineOption {
	return func(engine *Engine) {
		engine.SetAuthorizer(authorizer)
	}
}

// WithHook appends hook to the Engine lifecycle hooks.
func WithHook(hook Hook) EngineOption {
	return func(engine *Engine) {
		engine.RegisterHook(hook)
	}
}

// WithHooks appends hooks to the Engine lifecycle hooks.
func WithHooks(hooks ...Hook) EngineOption {
	return func(engine *Engine) {
		engine.RegisterHook(hooks...)
	}
}

// WithLogger overrides the logger used by Engine.
func WithLogger(logger *slog.Logger) EngineOption {
	return func(engine *Engine) {
		if engine != nil && logger != nil {
			engine.logger = logger
		}
	}
}

// WithDebug enables or disables debug logging on Engine.
func WithDebug(enabled bool) EngineOption {
	return func(engine *Engine) {
		if engine != nil {
			engine.debug = enabled
		}
	}
}
