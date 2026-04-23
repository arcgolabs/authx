package authjwt

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/collectionx"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimsMapper maps validated JWT claims into an authx authentication result.
type ClaimsMapper func(ctx context.Context, claims *Claims) (authx.AuthenticationResult, error)

// Option configures a JWT Provider.
type Option func(*Provider)

// Provider authenticates TokenCredential values by parsing and validating JWT claims.
type Provider struct {
	keyfunc       jwt.Keyfunc
	claimsMapper  ClaimsMapper
	parserOptions collectionx.List[jwt.ParserOption]
	validMethods  collectionx.List[string]
}

// NewProvider creates a JWT authentication provider.
func NewProvider(opts ...Option) *Provider {
	provider := &Provider{
		claimsMapper:  PrincipalClaimsMapper,
		parserOptions: collectionx.NewList[jwt.ParserOption](),
		validMethods:  collectionx.NewList[string](),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	return provider
}

// NewAuthenticationProvider creates an authx manager-compatible JWT provider.
func NewAuthenticationProvider(opts ...Option) authx.AuthenticationProvider {
	return authx.NewAuthenticationProvider[TokenCredential](NewProvider(opts...))
}

// WithKeyfunc configures the key function used by the JWT parser.
func WithKeyfunc(keyfunc jwt.Keyfunc) Option {
	return func(provider *Provider) {
		if provider != nil {
			provider.keyfunc = keyfunc
		}
	}
}

// WithHMACSecret configures HMAC verification. It defaults to HS256 when no method is provided.
func WithHMACSecret(secret []byte, methods ...string) Option {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.validMethods = collectionx.NewList(methods...)
		if provider.validMethods.IsEmpty() {
			provider.validMethods.Add(jwt.SigningMethodHS256.Alg())
		}
		provider.keyfunc = func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("validate signing method: %w", ErrInvalidToken)
			}
			return secret, nil
		}
	}
}

// WithValidMethods constrains acceptable JWT signing algorithms.
func WithValidMethods(methods ...string) Option {
	return func(provider *Provider) {
		if provider != nil {
			provider.validMethods = collectionx.NewList(methods...)
		}
	}
}

// WithParserOptions appends parser options for advanced JWT validation behavior.
func WithParserOptions(options ...jwt.ParserOption) Option {
	return func(provider *Provider) {
		if provider != nil {
			provider.parserOptions.Add(options...)
		}
	}
}

// WithClaimsMapper overrides the default authx.Principal mapping.
func WithClaimsMapper(mapper ClaimsMapper) Option {
	return func(provider *Provider) {
		if provider != nil && mapper != nil {
			provider.claimsMapper = mapper
		}
	}
}

// Authenticate validates credential and returns the mapped authentication result.
func (provider *Provider) Authenticate(
	ctx context.Context,
	credential TokenCredential,
) (authx.AuthenticationResult, error) {
	if provider == nil {
		return authx.AuthenticationResult{}, unauthenticatedError(ErrKeyfuncNotConfigured, "validate JWT provider")
	}
	if provider.keyfunc == nil {
		return authx.AuthenticationResult{}, unauthenticatedError(ErrKeyfuncNotConfigured, "validate JWT keyfunc")
	}

	tokenString := strings.TrimSpace(credential.Token)
	if tokenString == "" {
		return authx.AuthenticationResult{}, invalidCredentialError(ErrTokenEmpty, "validate JWT credential")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, provider.keyfunc, provider.jwtParserOptions()...)
	if err != nil {
		return authx.AuthenticationResult{}, unauthenticatedError(errors.Join(ErrInvalidToken, err), "parse JWT token")
	}
	if token == nil || !token.Valid {
		return authx.AuthenticationResult{}, unauthenticatedError(ErrInvalidToken, "validate JWT token")
	}

	result, err := provider.claimsMapper(ctx, claims)
	if err != nil {
		return authx.AuthenticationResult{}, fmt.Errorf("map JWT claims: %w", err)
	}
	return result, nil
}

func (provider *Provider) jwtParserOptions() []jwt.ParserOption {
	if provider.validMethods.IsEmpty() {
		return provider.parserOptions.Values()
	}
	options := collectionx.NewListWithCapacity[jwt.ParserOption](
		provider.parserOptions.Len()+1,
		jwt.WithValidMethods(provider.validMethods.Values()),
	)
	options.Merge(provider.parserOptions)
	return options.Values()
}

func invalidCredentialError(err error, message string) error {
	return fmt.Errorf("authx/jwt: %s: %w", message, errors.Join(authx.ErrInvalidAuthenticationCredential, err))
}

func unauthenticatedError(err error, message string) error {
	return fmt.Errorf("authx/jwt: %s: %w", message, errors.Join(authx.ErrUnauthenticated, err))
}
