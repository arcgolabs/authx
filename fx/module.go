package fx

import (
	pkgfx "github.com/DaiYuANg/arcgo/pkg/fx"
	"github.com/arcgolabs/authx"
	"go.uber.org/fx"
)

// EngineParams defines parameters for authx fxx module.
type EngineParams struct {
	fx.In

	// Options grouped from WithEngineOptions and NewAuthxModule arguments.
	Options []authx.EngineOption `group:"authx_engine_options"`
}

// EngineResult defines result for authx fxx module.
type EngineResult struct {
	fx.Out

	// Engine is the created authx engine.
	Engine *authx.Engine
}

// NewEngine creates an authx engine from grouped options.
func NewEngine(params EngineParams) EngineResult {
	return EngineResult{Engine: authx.NewEngine(params.Options...)}
}

// WithEngineOptions adds engine options into fxx option group.
func WithEngineOptions(opts ...authx.EngineOption) fx.Option {
	return pkgfx.ProvideOptionGroup[authx.Engine, authx.EngineOption]("authx_engine_options", opts...)
}

// NewAuthxModule creates an authx fxx module.
// It reuses authx.EngineOption as the module input options.
func NewAuthxModule(opts ...authx.EngineOption) fx.Option {
	return fx.Module("authx",
		fx.Provide(NewEngine),
		WithEngineOptions(opts...),
	)
}
