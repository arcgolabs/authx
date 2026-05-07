package rbac_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/authx/rbac"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func TestAuthorizerAllowsByCasbinPolicy(t *testing.T) {
	authorizer := rbac.NewCasbinAuthorizer(newTestEnforcer(t))

	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: authx.Principal{ID: "alice"},
		Resource:  "orders",
		Action:    "read",
	})

	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected decision allowed, got %#v", decision)
	}
	if decision.Reason != rbac.ReasonPolicyAllowed {
		t.Fatalf("expected reason %q, got %q", rbac.ReasonPolicyAllowed, decision.Reason)
	}
}

func TestAuthorizerDeniesByCasbinPolicy(t *testing.T) {
	authorizer := rbac.NewAuthorizer(newTestEnforcer(t))

	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "alice",
		Resource:  "orders",
		Action:    "delete",
	})

	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected decision denied")
	}
	if decision.Reason != rbac.ReasonPolicyDenied {
		t.Fatalf("expected reason %q, got %q", rbac.ReasonPolicyDenied, decision.Reason)
	}
}

func TestAuthorizerSupportsRoleManager(t *testing.T) {
	authorizer := rbac.NewAuthorizer(newTestEnforcer(t))

	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "bob",
		Resource:  "orders",
		Action:    "delete",
	})

	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected role policy to allow request")
	}
}

func TestAuthorizerSupportsDomainResolver(t *testing.T) {
	authorizer := rbac.NewAuthorizer(
		newDomainEnforcer(t),
		rbac.WithDomainResolver(func(context.Context, authx.AuthorizationModel) (string, bool, error) {
			return "tenant-a", true, nil
		}),
	)

	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "alice",
		Resource:  "orders",
		Action:    "read",
	})

	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected domain policy to allow request")
	}
}

func TestAuthorizerUsesCustomResolvers(t *testing.T) {
	authorizer := rbac.NewAuthorizer(
		newTestEnforcer(t),
		rbac.WithSubjectResolver(func(context.Context, authx.AuthorizationModel) (string, error) {
			return "alice", nil
		}),
		rbac.WithObjectResolver(func(context.Context, authx.AuthorizationModel) (string, error) {
			return "orders", nil
		}),
		rbac.WithActionResolver(func(context.Context, authx.AuthorizationModel) (string, error) {
			return "read", nil
		}),
	)

	decision, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: struct{}{},
	})

	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected custom resolvers to allow request")
	}
}

func TestAuthorizerRejectsInvalidSubject(t *testing.T) {
	authorizer := rbac.NewAuthorizer(newTestEnforcer(t))

	_, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: struct{}{},
		Resource:  "orders",
		Action:    "read",
	})

	assertAuthxCode(t, err, authx.ErrorCodeInvalidAuthorizationModel)
}

func TestAuthorizerRejectsNilEnforcer(t *testing.T) {
	authorizer := rbac.NewAuthorizer(nil)

	_, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "alice",
		Resource:  "orders",
		Action:    "read",
	})

	assertAuthxCode(t, err, authx.ErrorCodeAuthorizerNotConfigured)
}

func TestAuthorizerClassifiesEnforcerErrors(t *testing.T) {
	authorizer := rbac.NewAuthorizer(errorEnforcer{})

	_, err := authorizer.Authorize(context.Background(), authx.AuthorizationModel{
		Principal: "alice",
		Resource:  "orders",
		Action:    "read",
	})

	assertAuthxCode(t, err, authx.ErrorCodeInternal)
}

type errorEnforcer struct{}

func (errorEnforcer) Enforce(...any) (bool, error) {
	return false, errors.New("casbin failed")
}

func newTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()

	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(conf)
	if err != nil {
		t.Fatalf("create model: %v", err)
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	if _, err = enforcer.AddPolicy("alice", "orders", "read"); err != nil {
		t.Fatalf("add alice policy: %v", err)
	}
	if _, err = enforcer.AddPolicy("admin", "orders", "delete"); err != nil {
		t.Fatalf("add admin policy: %v", err)
	}
	if _, err = enforcer.AddGroupingPolicy("bob", "admin"); err != nil {
		t.Fatalf("add role policy: %v", err)
	}
	return enforcer
}

func newDomainEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()

	conf := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(conf)
	if err != nil {
		t.Fatalf("create model: %v", err)
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	if _, err = enforcer.AddPolicy("admin", "tenant-a", "orders", "read"); err != nil {
		t.Fatalf("add domain policy: %v", err)
	}
	if _, err = enforcer.AddGroupingPolicy("alice", "admin", "tenant-a"); err != nil {
		t.Fatalf("add domain role policy: %v", err)
	}
	return enforcer
}

func assertAuthxCode(t *testing.T, err error, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error")
	}
	if got := authx.ClassifyError(err).Code; got != code {
		t.Fatalf("expected code %q, got %q (%v)", code, got, err)
	}
}
