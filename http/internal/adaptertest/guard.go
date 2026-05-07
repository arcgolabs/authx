package adaptertest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
)

const (
	HeaderAuthorization = "Authorization"
	TokenUser           = "user-1"
	QueryTrace          = "trace"
)

type Snapshot struct {
	Method       string
	Path         string
	RoutePattern string
	PathID       string
	Token        string
	Trace        string
	PrincipalID  string
}

type ExpectedSnapshot struct {
	Method       string
	Path         string
	RoutePattern string
	PathID       string
	Token        string
	Trace        string
	PrincipalID  string
}

type credential struct {
	Token string
}

// NewGuard returns a deterministic guard shared by adapter behavior tests.
func NewGuard(record func(Snapshot)) *authhttp.Guard {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, input credential) (authx.AuthenticationResult, error) {
			if input.Token == "" || input.Token == "invalid-token" {
				return authx.AuthenticationResult{}, authx.NewError(
					authx.ErrorCodeUnauthenticated,
					"authenticate adapter test credential",
					"op", "adapter_test_authenticate",
				)
			}
			return authx.AuthenticationResult{
				Principal: authx.Principal{ID: input.Token},
			}, nil
		}),
	)

	authorizer := authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		if input.Action == "delete" {
			return authx.Decision{Allowed: false, Reason: "no_permission"}, nil
		}
		if input.Resource != "123" {
			return authx.Decision{Allowed: false, Reason: "missing_route_param"}, nil
		}
		return authx.Decision{Allowed: true}, nil
	})

	engine := authx.NewEngine(
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authorizer),
	)

	return authhttp.NewGuard(
		engine,
		authhttp.WithCredentialResolverFunc(func(_ context.Context, req authhttp.RequestInfo) (any, error) {
			token := req.Header(HeaderAuthorization)
			if token == "" {
				return nil, authx.NewError(
					authx.ErrorCodeInvalidAuthenticationCredential,
					"resolve adapter test credential",
					"op", "adapter_test_resolve_credential",
				)
			}
			return credential{Token: token}, nil
		}),
		authhttp.WithAuthorizationResolverFunc(func(_ context.Context, req authhttp.RequestInfo, principal any) (authx.AuthorizationModel, error) {
			pathID := req.PathParam("id")
			principalID := ""
			if typed, ok := principal.(authx.Principal); ok {
				principalID = typed.ID
			}

			if record != nil {
				record(Snapshot{
					Method:       req.Method,
					Path:         req.Path,
					RoutePattern: req.RoutePattern,
					PathID:       pathID,
					Token:        req.Header(HeaderAuthorization),
					Trace:        req.QueryValue(QueryTrace),
					PrincipalID:  principalID,
				})
			}

			action := "read"
			if req.Method == http.MethodDelete {
				action = "delete"
			}
			return authx.AuthorizationModel{
				Principal: principal,
				Action:    action,
				Resource:  pathID,
			}, nil
		}),
	)
}

func NewRequest(method string) *http.Request {
	req := httptest.NewRequestWithContext(
		context.Background(),
		method,
		"/orders/123?"+QueryTrace+"=abc",
		http.NoBody,
	)
	req.Header.Set(HeaderAuthorization, TokenUser)
	return req
}

func AssertSnapshot(t *testing.T, got Snapshot, expected ExpectedSnapshot) {
	t.Helper()

	if got.Method != expected.Method {
		t.Fatalf("method mismatch: got=%q expected=%q", got.Method, expected.Method)
	}
	if got.Path != expected.Path {
		t.Fatalf("path mismatch: got=%q expected=%q", got.Path, expected.Path)
	}
	if got.RoutePattern != expected.RoutePattern {
		t.Fatalf("route pattern mismatch: got=%q expected=%q", got.RoutePattern, expected.RoutePattern)
	}
	if got.PathID != expected.PathID {
		t.Fatalf("path param mismatch: got=%q expected=%q", got.PathID, expected.PathID)
	}
	if got.Token != expected.Token {
		t.Fatalf("token mismatch: got=%q expected=%q", got.Token, expected.Token)
	}
	if got.Trace != expected.Trace {
		t.Fatalf("query value mismatch: got=%q expected=%q", got.Trace, expected.Trace)
	}
	if got.PrincipalID != expected.PrincipalID {
		t.Fatalf("principal mismatch: got=%q expected=%q", got.PrincipalID, expected.PrincipalID)
	}
}

func AssertErrorBody(t *testing.T, body string, message string) {
	t.Helper()

	if !strings.Contains(body, `"error":"`+message+`"`) {
		t.Fatalf("expected error body %q to contain message %q", body, message)
	}
}
