package authhttp

import "github.com/DaiYuANg/arcgo/pkg/option"

// ApplyOptions applies non-nil option funcs to target.
func ApplyOptions[T any, O ~func(*T)](target *T, opts ...O) {
	option.Apply(target, opts...)
}
