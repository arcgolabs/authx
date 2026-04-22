// Package authhttp provides HTTP helpers and adapters for authx.
//
// Guard is the framework-facing adapter for request credential resolution and
// authorization model construction. TypedGuard is the generic variant for code
// that wants typed credentials and principals at the HTTP boundary, while still
// sharing the same authx.Engine runtime.
package authhttp
