package authjwt

import "errors"

var (
	// ErrTokenEmpty indicates that the JWT credential did not contain a token string.
	ErrTokenEmpty = errors.New("authx/jwt: token is empty")
	// ErrKeyfuncNotConfigured indicates that a provider has no verification key function.
	ErrKeyfuncNotConfigured = errors.New("authx/jwt: keyfunc not configured")
	// ErrInvalidToken indicates that JWT parsing or validation failed.
	ErrInvalidToken = errors.New("authx/jwt: invalid token")
	// ErrSubjectRequired indicates that default principal mapping could not find a subject.
	ErrSubjectRequired = errors.New("authx/jwt: subject is required")
)
