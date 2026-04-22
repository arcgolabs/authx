package authx

import (
	"context"
	"reflect"
)

// AuthenticationProvider is a runtime provider entry used by manager routing.
// CredentialType identifies which credential type this provider handles.
type AuthenticationProvider interface {
	CredentialType() reflect.Type
	AuthenticateAny(ctx context.Context, credential any) (AuthenticationResult, error)
}

// AuthenticationManager routes credential to one provider.
type AuthenticationManager interface {
	Authenticate(ctx context.Context, credential any) (AuthenticationResult, error)
}

// ProviderRegistrar registers authentication providers into a manager-compatible registry.
type ProviderRegistrar interface {
	Register(providers ...AuthenticationProvider)
}

// Authorizer evaluates access decision from principal + resource tuple.
type Authorizer interface {
	Authorize(ctx context.Context, input AuthorizationModel) (Decision, error)
}

// Hook provides lifecycle extension points around Check/Can.
type Hook interface {
	BeforeCheck(ctx context.Context, credential any) error
	AfterCheck(ctx context.Context, credential any, result AuthenticationResult, err error)
	BeforeCan(ctx context.Context, input AuthorizationModel) error
	AfterCan(ctx context.Context, input AuthorizationModel, decision Decision, err error)
}
