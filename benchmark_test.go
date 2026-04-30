package authx_test

import (
	"context"
	"testing"

	"github.com/arcgolabs/authx"
	collectionmapping "github.com/arcgolabs/collectionx/mapping"
)

type benchmarkCredential struct {
	Token string
}

type noopHook struct{}

func (noopHook) BeforeCheck(context.Context, any) error {
	return nil
}

func (noopHook) AfterCheck(context.Context, any, authx.AuthenticationResult, error) {}

func (noopHook) BeforeCan(context.Context, authx.AuthorizationModel) error {
	return nil
}

func (noopHook) AfterCan(context.Context, authx.AuthorizationModel, authx.Decision, error) {}

type benchmarkCase struct {
	name     string
	withHook bool
}

var benchmarkCases = []benchmarkCase{
	{name: "NoHook", withHook: false},
	{name: "WithHook", withHook: true},
}

func newBenchmarkEngine(withHook bool) *authx.Engine {
	manager := authx.NewProviderManager(
		authx.NewAuthenticationProviderFunc(func(_ context.Context, credential benchmarkCredential) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{
				Principal: authx.Principal{
					ID: credential.Token,
				},
			}, nil
		}),
	)
	authorizer := authx.AuthorizerFunc(func(_ context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
		_ = input
		return authx.Decision{Allowed: true}, nil
	})

	opts := []authx.EngineOption{
		authx.WithAuthenticationManager(manager),
		authx.WithAuthorizer(authorizer),
	}
	if withHook {
		opts = append(opts, authx.WithHook(noopHook{}))
	}

	return authx.NewEngine(opts...)
}

func BenchmarkEngineCheck(b *testing.B) {
	ctx := context.Background()
	credential := benchmarkCredential{Token: "u-1"}

	for _, benchCase := range benchmarkCases {
		b.Run(benchCase.name, func(b *testing.B) {
			benchmarkEngineCheck(ctx, b, credential, benchCase.withHook)
		})
	}
}

func BenchmarkEngineCan(b *testing.B) {
	ctx := context.Background()
	model := authx.AuthorizationModel{
		Principal: authx.Principal{ID: "u-1"},
		Action:    "query",
		Resource:  "order",
		Context: collectionmapping.NewMapFrom(map[string]any{
			"order_id": "1",
		}),
	}

	for _, benchCase := range benchmarkCases {
		b.Run(benchCase.name, func(b *testing.B) {
			benchmarkEngineCan(ctx, b, model, benchCase.withHook)
		})
	}
}

func BenchmarkEngineCheckThenCan(b *testing.B) {
	ctx := context.Background()
	credential := benchmarkCredential{Token: "u-1"}

	for _, benchCase := range benchmarkCases {
		b.Run(benchCase.name, func(b *testing.B) {
			benchmarkEngineCheckThenCan(ctx, b, credential, benchCase.withHook)
		})
	}
}

func benchmarkEngineCheck(
	ctx context.Context,
	b *testing.B,
	credential benchmarkCredential,
	withHook bool,
) {
	b.Helper()

	engine := newBenchmarkEngine(withHook)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result, err := engine.Check(ctx, credential)
		if err != nil {
			b.Fatalf("check failed: %v", err)
		}
		if result.Principal == nil {
			b.Fatal("principal should not be nil")
		}
	}
}

func benchmarkEngineCan(
	ctx context.Context,
	b *testing.B,
	model authx.AuthorizationModel,
	withHook bool,
) {
	b.Helper()

	engine := newBenchmarkEngine(withHook)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		decision, err := engine.Can(ctx, model)
		if err != nil {
			b.Fatalf("can failed: %v", err)
		}
		if !decision.Allowed {
			b.Fatal("decision should be allowed")
		}
	}
}

func benchmarkEngineCheckThenCan(
	ctx context.Context,
	b *testing.B,
	credential benchmarkCredential,
	withHook bool,
) {
	b.Helper()

	engine := newBenchmarkEngine(withHook)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result, err := engine.Check(ctx, credential)
		if err != nil {
			b.Fatalf("check failed: %v", err)
		}

		decision, err := engine.Can(ctx, authx.AuthorizationModel{
			Principal: result.Principal,
			Action:    "query",
			Resource:  "order",
			Context: collectionmapping.NewMapFrom(map[string]any{
				"order_id": "1",
			}),
		})
		if err != nil {
			b.Fatalf("can failed: %v", err)
		}
		if !decision.Allowed {
			b.Fatal("decision should be allowed")
		}
	}
}
