package rbac

import (
	"context"
	"fmt"

	"github.com/arcgolabs/authx"
	casbin "github.com/casbin/casbin/v2"
)

const (
	// ReasonPolicyAllowed indicates Casbin allowed the request.
	ReasonPolicyAllowed = "policy_allowed"
	// ReasonPolicyDenied indicates Casbin denied the request.
	ReasonPolicyDenied = "policy_denied"
)

// Enforcer is the Casbin Enforce surface used by Authorizer.
type Enforcer interface {
	Enforce(rvals ...any) (bool, error)
}

// SubjectResolver resolves a Casbin subject from an authx authorization input.
type SubjectResolver func(context.Context, authx.AuthorizationModel) (string, error)

// ObjectResolver resolves a Casbin object from an authx authorization input.
type ObjectResolver func(context.Context, authx.AuthorizationModel) (string, error)

// ActionResolver resolves a Casbin action from an authx authorization input.
type ActionResolver func(context.Context, authx.AuthorizationModel) (string, error)

// DomainResolver resolves an optional Casbin domain from an authx authorization input.
type DomainResolver func(context.Context, authx.AuthorizationModel) (string, bool, error)

// Option configures Authorizer behavior.
type Option func(*Authorizer)

// Authorizer delegates authorization decisions to a Casbin enforcer.
type Authorizer struct {
	enforcer        Enforcer
	subjectResolver SubjectResolver
	objectResolver  ObjectResolver
	actionResolver  ActionResolver
	domainResolver  DomainResolver
}

// NewAuthorizer constructs a Casbin-backed authx.Authorizer.
func NewAuthorizer(enforcer Enforcer, opts ...Option) *Authorizer {
	authorizer := &Authorizer{
		enforcer:        enforcer,
		subjectResolver: DefaultSubjectResolver,
		objectResolver:  DefaultObjectResolver,
		actionResolver:  DefaultActionResolver,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(authorizer)
		}
	}
	return authorizer
}

// NewCasbinAuthorizer constructs an Authorizer from a Casbin enforcer.
func NewCasbinAuthorizer(enforcer casbin.IEnforcer, opts ...Option) *Authorizer {
	return NewAuthorizer(enforcer, opts...)
}

// WithSubjectResolver overrides the default Casbin subject resolver.
func WithSubjectResolver(resolver SubjectResolver) Option {
	return func(authorizer *Authorizer) {
		if authorizer != nil && resolver != nil {
			authorizer.subjectResolver = resolver
		}
	}
}

// WithObjectResolver overrides the default Casbin object resolver.
func WithObjectResolver(resolver ObjectResolver) Option {
	return func(authorizer *Authorizer) {
		if authorizer != nil && resolver != nil {
			authorizer.objectResolver = resolver
		}
	}
}

// WithActionResolver overrides the default Casbin action resolver.
func WithActionResolver(resolver ActionResolver) Option {
	return func(authorizer *Authorizer) {
		if authorizer != nil && resolver != nil {
			authorizer.actionResolver = resolver
		}
	}
}

// WithDomainResolver enables domain-aware Casbin enforcement.
func WithDomainResolver(resolver DomainResolver) Option {
	return func(authorizer *Authorizer) {
		if authorizer != nil {
			authorizer.domainResolver = resolver
		}
	}
}

// Authorize evaluates input using the configured Casbin enforcer.
func (authorizer *Authorizer) Authorize(
	ctx context.Context,
	input authx.AuthorizationModel,
) (authx.Decision, error) {
	if authorizer == nil || authorizer.enforcer == nil {
		return authx.Decision{}, authx.NewError(
			authx.ErrorCodeAuthorizerNotConfigured,
			"validate RBAC authorizer",
			"op", "authorize",
			"stage", "validate_authorizer",
		)
	}

	subject, object, action, domain, hasDomain, err := authorizer.resolveRequest(ctx, input)
	if err != nil {
		return authx.Decision{}, err
	}

	args := []any{subject, object, action}
	if hasDomain {
		args = []any{subject, domain, object, action}
	}

	allowed, err := authorizer.enforcer.Enforce(args...)
	if err != nil {
		return authx.Decision{}, authx.WrapError(
			err,
			authx.ErrorCodeInternal,
			"enforce RBAC policy",
			"op", "authorize",
			"stage", "enforce_policy",
			"subject", subject,
			"object", object,
			"action", action,
			"domain", domain,
			"has_domain", hasDomain,
		)
	}
	if allowed {
		return authx.Decision{Allowed: true, Reason: ReasonPolicyAllowed}, nil
	}
	return authx.Decision{Allowed: false, Reason: ReasonPolicyDenied}, nil
}

func (authorizer *Authorizer) resolveRequest(
	ctx context.Context,
	input authx.AuthorizationModel,
) (subject string, object string, action string, domain string, hasDomain bool, err error) {
	subject, err = authorizer.subjectResolver(ctx, input)
	if err != nil {
		return "", "", "", "", false, err
	}
	object, err = authorizer.objectResolver(ctx, input)
	if err != nil {
		return "", "", "", "", false, err
	}
	action, err = authorizer.actionResolver(ctx, input)
	if err != nil {
		return "", "", "", "", false, err
	}
	if authorizer.domainResolver != nil {
		domain, hasDomain, err = authorizer.domainResolver(ctx, input)
		if err != nil {
			return "", "", "", "", false, err
		}
	}
	return subject, object, action, domain, hasDomain, nil
}

// DefaultSubjectResolver resolves authx.Principal.ID, string principals, or fmt.Stringer principals.
func DefaultSubjectResolver(_ context.Context, input authx.AuthorizationModel) (string, error) {
	switch principal := input.Principal.(type) {
	case authx.Principal:
		if principal.ID != "" {
			return principal.ID, nil
		}
	case *authx.Principal:
		if principal != nil && principal.ID != "" {
			return principal.ID, nil
		}
	case string:
		if principal != "" {
			return principal, nil
		}
	case fmt.Stringer:
		subject := principal.String()
		if subject != "" {
			return subject, nil
		}
	}
	return "", authx.NewError(
		authx.ErrorCodeInvalidAuthorizationModel,
		"resolve RBAC subject",
		"op", "authorize",
		"stage", "resolve_subject",
	)
}

// DefaultObjectResolver resolves AuthorizationModel.Resource.
func DefaultObjectResolver(_ context.Context, input authx.AuthorizationModel) (string, error) {
	if input.Resource != "" {
		return input.Resource, nil
	}
	return "", authx.NewError(
		authx.ErrorCodeInvalidAuthorizationModel,
		"resolve RBAC object",
		"op", "authorize",
		"stage", "resolve_object",
	)
}

// DefaultActionResolver resolves AuthorizationModel.Action.
func DefaultActionResolver(_ context.Context, input authx.AuthorizationModel) (string, error) {
	if input.Action != "" {
		return input.Action, nil
	}
	return "", authx.NewError(
		authx.ErrorCodeInvalidAuthorizationModel,
		"resolve RBAC action",
		"op", "authorize",
		"stage", "resolve_action",
	)
}
