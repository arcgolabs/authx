package authhttp_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
)

type typedCredential struct {
	UserID string
}

func TestTypedGuardRequireTyped(t *testing.T) {
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(authx.NewProviderManager(
			authx.NewAuthenticationProviderFunc(func(
				_ context.Context,
				credential typedCredential,
			) (authx.AuthenticationResult, error) {
				return authx.AuthenticationResult{
					Principal: authx.Principal{ID: credential.UserID},
				}, nil
			}),
		)),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
			_ = input
			return authx.Decision{Allowed: true}, nil
		})),
	)

	guard := authhttp.NewTypedGuard[typedCredential, authx.Principal](
		engine,
		authhttp.WithTypedCredentialResolverFunc[typedCredential, authx.Principal](func(
			_ context.Context,
			req authhttp.RequestInfo,
		) (typedCredential, error) {
			return typedCredential{UserID: req.Header("X-User-ID")}, nil
		}),
		authhttp.WithTypedAuthorizationResolverFunc[typedCredential, authx.Principal](func(
			_ context.Context,
			req authhttp.RequestInfo,
			principal authx.Principal,
		) (authx.AuthorizationModel, error) {
			return authx.AuthorizationModel{
				Principal: principal,
				Action:    "query",
				Resource:  req.PathParam("resource"),
			}, nil
		}),
	)

	headers := make(http.Header)
	headers.Set("X-User-ID", "u-1")
	reqInfo := authhttp.RequestInfo{
		Headers:    headers,
		PathParams: map[string]string{"resource": "order"},
	}
	if got := reqInfo.Header("X-User-ID"); got != "u-1" {
		t.Fatalf("unexpected request header value before require: %q", got)
	}

	principal, decision, err := guard.RequireTyped(context.Background(), reqInfo)
	if err != nil {
		t.Fatalf("require typed failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed decision")
	}
	if principal.ID != "u-1" {
		t.Fatalf("unexpected principal id: %s", principal.ID)
	}
}

func TestTypedGuardPrincipalTypeMismatch(t *testing.T) {
	engine := authx.NewEngine(
		authx.WithAuthenticationManager(authx.NewProviderManager(
			authx.NewAuthenticationProviderFunc(func(
				_ context.Context,
				_ typedCredential,
			) (authx.AuthenticationResult, error) {
				return authx.AuthenticationResult{
					Principal: "wrong-principal-type",
				}, nil
			}),
		)),
		authx.WithAuthorizer(authx.AuthorizerFunc(func(_ context.Context, _ authx.AuthorizationModel) (authx.Decision, error) {
			return authx.Decision{Allowed: true}, nil
		})),
	)

	guard := authhttp.NewTypedGuard[typedCredential, authx.Principal](
		engine,
		authhttp.WithTypedCredentialResolverFunc[typedCredential, authx.Principal](func(
			_ context.Context,
			_ authhttp.RequestInfo,
		) (typedCredential, error) {
			return typedCredential{UserID: "u-1"}, nil
		}),
		authhttp.WithTypedAuthorizationResolverFunc[typedCredential, authx.Principal](func(
			_ context.Context,
			_ authhttp.RequestInfo,
			principal authx.Principal,
		) (authx.AuthorizationModel, error) {
			return authx.AuthorizationModel{Principal: principal, Action: "query", Resource: "order"}, nil
		}),
	)

	_, _, err := guard.RequireTyped(context.Background(), authhttp.RequestInfo{})
	if err == nil {
		t.Fatalf("expected principal type mismatch error")
	}
	if !errors.Is(err, authhttp.ErrPrincipalTypeMismatch) {
		t.Fatalf("unexpected error: %v", err)
	}
}
