package authjwt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arcgolabs/authx"
	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/golang-jwt/jwt/v5"
	"github.com/samber/oops"
)

// ClaimsMapper maps validated JWT claims into an authx authentication result.
type ClaimsMapper func(ctx context.Context, claims *Claims) (authx.AuthenticationResult, error)

// Option configures a JWT Provider.
type Option func(*Provider)

// Provider authenticates TokenCredential values by parsing and validating JWT claims.
type Provider struct {
	keyfunc       jwt.Keyfunc
	claimsMapper  ClaimsMapper
	parserOptions *collectionlist.List[jwt.ParserOption]
	validMethods  *collectionlist.List[string]
}

// NewProvider creates a JWT authentication provider.
func NewProvider(opts ...Option) *Provider {
	provider := &Provider{
		claimsMapper:  PrincipalClaimsMapper,
		parserOptions: collectionlist.NewList[jwt.ParserOption](),
		validMethods:  collectionlist.NewList[string](),
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

// WithHMACSecret configures HMAC verification with a single static secret.
// It defaults to HS256 when no method is provided.
//
// For multi-key use cases (for example rotation with kid), use WithHMACSecrets.
func WithHMACSecret(secret []byte, methods ...string) Option {
	if len(secret) == 0 {
		return func(provider *Provider) {}
	}
	secretCopy := copySecret(secret)
	return WithHMACSecrets(map[string][]byte{"": secretCopy}, methods...)
}

// WithHMACSecrets configures HMAC verification with one or more secrets.
//
// If a token has a kid header, that kid must exist in keys.
// If no kid is set, behavior is:
//   - if exactly one secret is configured, use it as fallback
//   - if exactly one default key is configured with kid "", use it
//   - otherwise validation fails.
func WithHMACSecrets(keys map[string][]byte, methods ...string) Option {
	return func(provider *Provider) {
		if provider == nil || len(keys) == 0 {
			return
		}
		provider.validMethods = collectionlist.NewList(methods...)
		if provider.validMethods.IsEmpty() {
			provider.validMethods.Add(jwt.SigningMethodHS256.Alg())
		}

		configuredKeys := make(map[string][]byte, len(keys))
		for kid, secret := range keys {
			configuredKeys[kid] = copySecret(secret)
		}

		provider.keyfunc = func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("validate signing method: %w", ErrInvalidToken)
			}
			if configuredKeys == nil {
				return nil, fmt.Errorf("resolve signing key: %w", ErrInvalidToken)
			}

			kid := parseStringHeader(token.Header, "kid")
			if kid == "" {
				if defaultSecret, ok := configuredKeys[""]; ok {
					return defaultSecret, nil
				}
				if len(configuredKeys) == 1 {
					for _, secret := range configuredKeys {
						return secret, nil
					}
				}
				return nil, fmt.Errorf("resolve signing key by kid: %w", ErrInvalidToken)
			}

			secret, ok := configuredKeys[kid]
			if !ok {
				return nil, fmt.Errorf("resolve signing key by kid: %w", ErrInvalidToken)
			}
			return secret, nil
		}
	}
}

// parseStringHeader returns token header value only when it is a non-empty string.
func parseStringHeader(header map[string]any, key string) string {
	if header == nil {
		return ""
	}
	value, ok := header[key]
	if !ok {
		return ""
	}
	strValue, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(strValue)
}

// copySecret returns a defensive copy of the provided secret.
func copySecret(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	return secretCopy
}

// WithValidMethods constrains acceptable JWT signing algorithms.
func WithValidMethods(methods ...string) Option {
	return func(provider *Provider) {
		if provider != nil {
			provider.validMethods = collectionlist.NewList(methods...)
		}
	}
}

// WithIssuer constrains the `iss` claim to the provided issuer.
func WithIssuer(issuer string) Option {
	return func(provider *Provider) {
		if provider != nil && issuer != "" {
			provider.parserOptions.Add(jwt.WithIssuer(issuer))
		}
	}
}

// WithAudience constrains the `aud` claim to include at least one expected audience.
func WithAudience(audiences ...string) Option {
	return func(provider *Provider) {
		if provider == nil || len(audiences) == 0 {
			return
		}
		provider.parserOptions.Add(jwt.WithAudience(audiences...))
	}
}

// WithRequiredSubject constrains the `sub` claim to a specific expected value.
func WithRequiredSubject(subject string) Option {
	return func(provider *Provider) {
		if provider != nil && subject != "" {
			provider.parserOptions.Add(jwt.WithSubject(subject))
		}
	}
}

// WithClockSkew allows time-based claim validation tolerances.
func WithClockSkew(skew time.Duration) Option {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.parserOptions.Add(jwt.WithLeeway(skew))
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
	options := collectionlist.NewListWithCapacity[jwt.ParserOption](
		provider.parserOptions.Len()+1,
		jwt.WithValidMethods(provider.validMethods.Values()),
	)
	options.Merge(provider.parserOptions)
	return options.Values()
}

func invalidCredentialError(err error, message string) error {
	return classifiedError(errors.Join(authx.ErrInvalidAuthenticationCredential, err), message)
}

func unauthenticatedError(err error, message string) error {
	return classifiedError(errors.Join(authx.ErrUnauthenticated, err), message)
}

func classifiedError(err error, message string) error {
	classification := authx.ClassifyError(err)
	return oops.In("authx/jwt").
		Code(classification.Code).
		With(classification.OopsFields()...).
		Wrapf(err, "authx/jwt: %s", message)
}
