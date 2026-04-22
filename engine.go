package authx

import (
	"context"
	"log/slog"
	"reflect"
	"slices"
	"sync"

	"github.com/DaiYuANg/arcgo/pkg/option"
	"github.com/samber/oops"
)

// Engine separates authentication (Check) and authorization (Can).
type Engine struct {
	mu     sync.RWMutex
	authn  AuthenticationManager
	authz  Authorizer
	hooks  []Hook
	logger *slog.Logger
	debug  bool
}

// NewEngine constructs an Engine from opts.
func NewEngine(opts ...EngineOption) *Engine {
	engine := &Engine{logger: slog.Default()}
	option.Apply(engine, opts...)
	engine.logDebug("authx engine created", "hooks", len(engine.hooks), "has_authn", engine.authn != nil, "has_authz", engine.authz != nil)
	return engine
}

// SetAuthenticationManager updates the authentication manager used by Check.
func (engine *Engine) SetAuthenticationManager(manager AuthenticationManager) {
	if engine == nil {
		return
	}
	engine.mu.Lock()
	engine.authn = manager
	engine.mu.Unlock()
	engine.logDebug("authentication manager configured", "manager_type", reflect.TypeOf(manager))
}

// RegisterProvider appends providers to the engine's provider-backed authentication manager.
func (engine *Engine) RegisterProvider(providers ...AuthenticationProvider) error {
	if engine == nil {
		return oops.In("authx").
			With("op", "register_provider", "stage", "validate_engine").
			Wrapf(ErrNilEngine, "validate engine")
	}
	if len(providers) == 0 {
		return nil
	}

	registrar, err := engine.resolveProviderRegistrar()
	if err != nil {
		return err
	}
	registrar.Register(providers...)
	engine.logDebug("authentication providers registered", "providers", len(providers), "registrar_type", reflect.TypeOf(registrar))
	return nil
}

func (engine *Engine) resolveProviderRegistrar() (ProviderRegistrar, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()

	if engine.authn == nil {
		manager := NewProviderManager()
		engine.authn = manager
		return manager, nil
	}

	registrar, ok := engine.authn.(ProviderRegistrar)
	if !ok {
		return nil, oops.In("authx").
			With("op", "register_provider", "stage", "resolve_registrar", "manager_type", reflect.TypeOf(engine.authn)).
			Wrapf(ErrAuthenticationProviderRegistrationUnsupported, "resolve provider registrar")
	}
	return registrar, nil
}

// SetAuthorizer updates the authorizer used by Can.
func (engine *Engine) SetAuthorizer(authorizer Authorizer) {
	if engine == nil {
		return
	}
	engine.mu.Lock()
	engine.authz = authorizer
	engine.mu.Unlock()
	engine.logDebug("authorizer configured", "authorizer_type", reflect.TypeOf(authorizer))
}

// AddHook appends hook to the engine lifecycle hooks.
func (engine *Engine) AddHook(hook Hook) {
	engine.RegisterHook(hook)
}

// RegisterHook appends hooks to the engine lifecycle hooks.
func (engine *Engine) RegisterHook(hooks ...Hook) {
	if engine == nil || len(hooks) == 0 {
		return
	}

	added := 0
	engine.mu.Lock()
	for _, hook := range hooks {
		if hook == nil {
			continue
		}
		engine.hooks = append(engine.hooks, hook)
		added++
	}
	hookCount := len(engine.hooks)
	engine.mu.Unlock()
	engine.logDebug("authx hooks registered", "hooks_added", added, "hooks", hookCount)
}

// Check authenticates credential and returns principal.
func (engine *Engine) Check(ctx context.Context, credential any) (AuthenticationResult, error) {
	if credential == nil {
		return AuthenticationResult{}, oops.In("authx").
			With("op", "check", "stage", "validate_credential").
			Wrapf(ErrInvalidAuthenticationCredential, "validate authentication credential")
	}
	credentialType := reflect.TypeOf(credential)
	engine.logDebug("authx check started", "credential_type", credentialType)

	authn, hooks := engine.snapshotCheckDependencies()
	if authn == nil {
		engine.logError("authx check failed", "credential_type", credentialType, "error", ErrAuthenticationManagerNotConfigured)
		return AuthenticationResult{}, oops.In("authx").
			With("op", "check", "stage", "resolve_manager", "credential_type", credentialType).
			Wrapf(ErrAuthenticationManagerNotConfigured, "resolve authentication manager")
	}

	if beforeCheckErr := runBeforeCheckHooks(ctx, hooks, credential); beforeCheckErr != nil {
		engine.logError("authx check before hook failed", "credential_type", credentialType, "error", beforeCheckErr)
		return AuthenticationResult{}, beforeCheckErr
	}

	result, err := authn.Authenticate(ctx, credential)
	runAfterCheckHooks(ctx, hooks, credential, result, err)
	if err != nil {
		engine.logError("authx check failed", "credential_type", credentialType, "error", err)
		return AuthenticationResult{}, oops.In("authx").
			With("op", "check", "credential_type", credentialType).
			Wrapf(err, "authenticate credential")
	}
	engine.logDebug("authx check completed", "credential_type", credentialType, "principal_type", reflect.TypeOf(result.Principal))
	return result, nil
}

// Can authorizes principal access to action/resource.
func (engine *Engine) Can(ctx context.Context, input AuthorizationModel) (Decision, error) {
	if err := validateAuthorizationModel(input); err != nil {
		return Decision{}, oops.In("authx").
			With(
				"op", "authorize",
				"stage", "validate_input",
				"action", input.Action,
				"resource", input.Resource,
				"principal_type", reflect.TypeOf(input.Principal),
			).
			Wrapf(err, "validate authorization model")
	}
	engine.logDebug("authx can started", "action", input.Action, "resource", input.Resource)

	authorizer, hooks := engine.snapshotCanDependencies()
	if authorizer == nil {
		engine.logError("authx can failed", "action", input.Action, "resource", input.Resource, "error", ErrAuthorizerNotConfigured)
		return Decision{}, oops.In("authx").
			With("op", "authorize", "stage", "resolve_authorizer", "action", input.Action, "resource", input.Resource).
			Wrapf(ErrAuthorizerNotConfigured, "resolve authorizer")
	}

	if beforeCanErr := runBeforeCanHooks(ctx, hooks, input); beforeCanErr != nil {
		engine.logError("authx can before hook failed", "action", input.Action, "resource", input.Resource, "error", beforeCanErr)
		return Decision{}, beforeCanErr
	}

	decision, err := authorizer.Authorize(ctx, input)
	runAfterCanHooks(ctx, hooks, input, decision, err)
	if err != nil {
		engine.logError("authx can failed", "action", input.Action, "resource", input.Resource, "error", err)
		return Decision{}, oops.In("authx").
			With("op", "authorize", "action", input.Action, "resource", input.Resource).
			Wrapf(err, "authorize request")
	}
	engine.logDebug("authx can completed", "action", input.Action, "resource", input.Resource, "allowed", decision.Allowed, "policy_id", decision.PolicyID)
	return decision, nil
}

func (engine *Engine) snapshotCheckDependencies() (AuthenticationManager, []Hook) {
	if engine == nil {
		return nil, nil
	}

	engine.mu.RLock()
	authn := engine.authn
	hooks := slices.Clone(engine.hooks)
	engine.mu.RUnlock()
	return authn, hooks
}

func (engine *Engine) snapshotCanDependencies() (Authorizer, []Hook) {
	if engine == nil {
		return nil, nil
	}

	engine.mu.RLock()
	authorizer := engine.authz
	hooks := slices.Clone(engine.hooks)
	engine.mu.RUnlock()
	return authorizer, hooks
}

func runBeforeCheckHooks(ctx context.Context, hooks []Hook, credential any) error {
	for _, hook := range hooks {
		if hook == nil {
			continue
		}
		if err := hook.BeforeCheck(ctx, credential); err != nil {
			return oops.In("authx").
				With(
					"op", "check",
					"stage", "before_hook",
					"credential_type", reflect.TypeOf(credential),
					"hook_type", reflect.TypeOf(hook),
				).
				Wrapf(err, "before check hook")
		}
	}
	return nil
}

func runAfterCheckHooks(ctx context.Context, hooks []Hook, credential any, result AuthenticationResult, err error) {
	for _, hook := range hooks {
		if hook != nil {
			hook.AfterCheck(ctx, credential, result, err)
		}
	}
}

func runBeforeCanHooks(ctx context.Context, hooks []Hook, input AuthorizationModel) error {
	for _, hook := range hooks {
		if hook == nil {
			continue
		}
		if err := hook.BeforeCan(ctx, input); err != nil {
			return oops.In("authx").
				With(
					"op", "authorize",
					"stage", "before_hook",
					"action", input.Action,
					"resource", input.Resource,
					"hook_type", reflect.TypeOf(hook),
				).
				Wrapf(err, "before authorization hook")
		}
	}
	return nil
}

func runAfterCanHooks(ctx context.Context, hooks []Hook, input AuthorizationModel, decision Decision, err error) {
	for _, hook := range hooks {
		if hook != nil {
			hook.AfterCan(ctx, input, decision, err)
		}
	}
}

func validateAuthorizationModel(input AuthorizationModel) error {
	if input.Action == "" || input.Resource == "" {
		return oops.In("authx").
			With("op", "validate_authorization_model", "action", input.Action, "resource", input.Resource, "principal_type", reflect.TypeOf(input.Principal)).
			Wrapf(ErrInvalidAuthorizationModel, "authorization action and resource are required")
	}
	if input.Principal == nil {
		return oops.In("authx").
			With("op", "validate_authorization_model", "action", input.Action, "resource", input.Resource).
			Wrapf(ErrInvalidAuthorizationModel, "authorization principal is required")
	}
	return nil
}

func (engine *Engine) logDebug(msg string, attrs ...any) {
	if engine == nil || engine.logger == nil || !engine.debug {
		return
	}
	engine.logger.Debug(msg, attrs...)
}

func (engine *Engine) logError(msg string, attrs ...any) {
	if engine == nil || engine.logger == nil {
		return
	}
	engine.logger.Error(msg, attrs...)
}
