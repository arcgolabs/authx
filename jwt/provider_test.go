package authjwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	collectionlist "github.com/arcgolabs/collectionx/list"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderAuthenticatesHMACToken(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		Roles:       []string{"admin"},
		Permissions: []string{"orders:read"},
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			Issuer:    "issuer",
			Audience:  []string{"api"},
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "token-1",
		},
	})

	provider := authjwt.NewProvider(authjwt.WithHMACSecret(secret))

	result, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	require.NoError(t, err)
	principal, ok := result.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "u1", principal.ID)
	assert.Equal(t, []string{"admin"}, principal.Roles.Values())
	assert.Equal(t, []string{"orders:read"}, principal.Permissions.Values())
	assert.Equal(t, "issuer", principal.Attributes.GetOrDefault("issuer", ""))
	audience, ok := principal.Attributes.Get("audience")
	require.True(t, ok)
	audienceList, ok := audience.(*collectionlist.List[string])
	require.True(t, ok)
	assert.Equal(t, []string{"api"}, audienceList.Values())
	assert.Equal(t, "token-1", principal.Attributes.GetOrDefault("jwt_id", ""))
}

func TestNewAuthenticationProviderWorksWithProviderManager(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	manager := authx.NewProviderManager(authjwt.NewAuthenticationProvider(authjwt.WithHMACSecret(secret)))

	result, err := manager.Authenticate(context.Background(), authjwt.TokenCredential{Token: token})
	require.NoError(t, err)
	principal, ok := result.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "u1", principal.ID)
}

func TestProviderRejectsEmptyToken(t *testing.T) {
	provider := authjwt.NewProvider(authjwt.WithHMACSecret([]byte("secret")))

	_, err := provider.Authenticate(context.Background(), authjwt.TokenCredential{Token: " "})
	assertJWTErrorCode(t, err, authjwt.ErrorCodeTokenEmpty)
}

func TestClassifyErrorUsesJWTCodeWithoutOopsFields(t *testing.T) {
	err := oops.In("external").Code(authjwt.ErrorCodeInvalidToken).New("parse JWT token")

	got := authjwt.ClassifyError(err)

	assert.Equal(t, authx.ErrorCategoryAuthentication, got.Category)
	assert.Equal(t, authjwt.ErrorCodeInvalidToken, got.Code)
	assert.Equal(t, "unauthorized", got.SafeMessage)
}

func TestNewErrorCreatesJWTClassification(t *testing.T) {
	err := authjwt.NewError(authjwt.ErrorCodeSubjectRequired, "map JWT subject")

	got := authjwt.ClassifyError(err)

	assert.Equal(t, authx.ErrorCategoryAuthentication, got.Category)
	assert.Equal(t, authjwt.ErrorCodeSubjectRequired, got.Code)
	assert.Equal(t, "unauthorized", got.SafeMessage)
}

func TestProviderRejectsInvalidSigningMethod(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS384, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(authjwt.WithHMACSecret(secret))

	_, err := provider.Authenticate(context.Background(), authjwt.TokenCredential{Token: token})
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderValidatesIssuer(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			Issuer:    "token-issuer",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithIssuer("service-a"),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderValidatesAudience(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			Audience:  []string{"api"},
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithAudience("admin"),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderRequiresAllAudiences(t *testing.T) {
	secret := []byte("secret")
	validToken := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			Audience:  []string{"api", "admin"},
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	invalidToken := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			Audience:  []string{"api"},
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithAllAudiences("api", "admin"),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(validToken))
	require.NoError(t, err)

	_, invalidErr := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(invalidToken))
	assertJWTErrorCode(t, invalidErr, authjwt.ErrorCodeInvalidToken)
}

func TestProviderEnforcesRequiredSubject(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "actual-subject",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithRequiredSubject("expected-subject"),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderEnforcesRequiredIssuedAt(t *testing.T) {
	secret := []byte("secret")
	tokenWithoutIAT := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokenWithIAT := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithRequiredIssuedAt(),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithoutIAT))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)

	_, withIatErr := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithIAT))
	require.NoError(t, withIatErr)
}

func TestProviderEnforcesRequiredExpiration(t *testing.T) {
	secret := []byte("secret")
	tokenWithoutExp := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject: "u1",
		},
	})
	tokenWithExp := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithRequiredExpiration(),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithoutExp))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)

	_, withExpErr := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithExp))
	require.NoError(t, withExpErr)
}

func TestProviderEnforcesRequiredNotBefore(t *testing.T) {
	secret := []byte("secret")
	tokenWithoutNBF := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokenWithNBF := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			NotBefore: jwtlib.NewNumericDate(time.Now().Add(-time.Second)),
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithRequiredNotBefore(),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithoutNBF))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)

	_, withNbfErr := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(tokenWithNBF))
	require.NoError(t, withNbfErr)
}

func TestProviderSupportsClockSkewForNotBefore(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			NotBefore: jwtlib.NewNumericDate(time.Now().Add(45 * time.Second)),
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})
	noSkewProvider := authjwt.NewProvider(authjwt.WithHMACSecret(secret))
	_, noSkewErr := noSkewProvider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, noSkewErr, authjwt.ErrorCodeInvalidToken)

	withSkewProvider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithClockSkew(60*time.Second),
	)
	_, withSkewErr := withSkewProvider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	require.NoError(t, withSkewErr)
}

func TestProviderAuthenticatesTokenWithKID(t *testing.T) {
	secrets := map[string][]byte{
		"old": []byte("old-secret"),
		"new": []byte("new-secret"),
	}
	token := signTokenWithKID(t, secrets["new"], jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, "new")
	provider := authjwt.NewProvider(authjwt.WithHMACSecrets(secrets))

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	require.NoError(t, err)
}

func TestProviderRejectsMissingKIDWithMultipleSecrets(t *testing.T) {
	secrets := map[string][]byte{
		"old": []byte("old-secret"),
		"new": []byte("new-secret"),
	}
	token := signTokenWithKID(t, secrets["new"], jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, "")
	provider := authjwt.NewProvider(authjwt.WithHMACSecrets(secrets))

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderRejectsUnknownKIDWithMultipleSecrets(t *testing.T) {
	secrets := map[string][]byte{
		"old": []byte("old-secret"),
		"new": []byte("new-secret"),
	}
	token := signTokenWithKID(t, secrets["new"], jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, "missing")
	provider := authjwt.NewProvider(authjwt.WithHMACSecrets(secrets))

	_, err := provider.Authenticate(context.Background(), authjwt.NewTokenCredential(token))
	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}

func TestProviderUsesClaimsMapper(t *testing.T) {
	secret := []byte("secret")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithClaimsMapper(func(_ context.Context, claims *authjwt.Claims) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{Principal: "mapped:" + claims.Subject}, nil
		}),
	)

	result, err := provider.Authenticate(context.Background(), authjwt.TokenCredential{Token: token})
	require.NoError(t, err)
	assert.Equal(t, "mapped:u1", result.Principal)
}

func TestProviderRejectsMapperError(t *testing.T) {
	secret := []byte("secret")
	mapperErr := errors.New("mapper failed")
	token := signToken(t, secret, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "u1",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	provider := authjwt.NewProvider(
		authjwt.WithHMACSecret(secret),
		authjwt.WithClaimsMapper(func(context.Context, *authjwt.Claims) (authx.AuthenticationResult, error) {
			return authx.AuthenticationResult{}, mapperErr
		}),
	)

	_, err := provider.Authenticate(context.Background(), authjwt.TokenCredential{Token: token})
	require.Error(t, err)
	assert.Equal(t, authx.ErrorCodeInternal, authjwt.ClassifyError(err).Code)
	assert.Contains(t, err.Error(), mapperErr.Error())
}

func signToken(t *testing.T, secret []byte, method jwtlib.SigningMethod, claims authjwt.Claims) string {
	t.Helper()

	token := jwtlib.NewWithClaims(method, claims)
	signed, err := token.SignedString(secret)
	require.NoError(t, err)
	return signed
}

func assertJWTErrorCode(t *testing.T, err error, code string) {
	t.Helper()

	require.Error(t, err)
	assert.Equal(t, code, authjwt.ClassifyError(err).Code)
}

func signTokenWithKID(
	t *testing.T,
	secret []byte,
	method jwtlib.SigningMethod,
	claims authjwt.Claims,
	kid string,
) string {
	t.Helper()

	token := jwtlib.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(secret)
	require.NoError(t, err)
	return signed
}
