// Package authjwt provides JWT authentication providers for authx.
//
// The package is transport-agnostic: it validates JWT token strings and maps
// claims into authx principals, but it does not parse HTTP headers or cookies.
package authjwt
