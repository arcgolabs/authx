package authjwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerAuthenticationProviderSelectsProviderByIssuer(t *testing.T) {
	secretA := []byte("issuer-a-secret")
	secretB := []byte("issuer-b-secret")
	provider := authjwt.NewIssuerAuthenticationProvider(
		map[string]authx.TypedAuthenticationProvider[authjwt.TokenCredential]{
			"issuer-a": authjwt.NewProvider(
				authjwt.WithHMACSecret(secretA),
				authjwt.WithIssuer("issuer-a"),
			),
			"issuer-b": authjwt.NewProvider(
				authjwt.WithHMACSecret(secretB),
				authjwt.WithIssuer("issuer-b"),
			),
		},
	)
	manager := authx.NewProviderManager(provider)
	token := signToken(t, secretB, jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user-b",
			Issuer:    "issuer-b",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	result, err := manager.Authenticate(context.Background(), authjwt.NewTokenCredential(token))

	require.NoError(t, err)
	principal, ok := result.Principal.(authx.Principal)
	require.True(t, ok)
	assert.Equal(t, "user-b", principal.ID)
	assert.Equal(t, "issuer-b", principal.Attributes.GetOrDefault("issuer", ""))
}

func TestIssuerAuthenticationProviderRejectsMissingIssuer(t *testing.T) {
	provider := authjwt.NewIssuerAuthenticationProvider(
		map[string]authx.TypedAuthenticationProvider[authjwt.TokenCredential]{
			"issuer-a": authjwt.NewProvider(authjwt.WithHMACSecret([]byte("secret"))),
		},
	)
	token := signToken(t, []byte("secret"), jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user-a",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	_, err := provider.AuthenticateAny(context.Background(), authjwt.NewTokenCredential(token))

	assertJWTErrorCode(t, err, authjwt.ErrorCodeIssuerRequired)
}

func TestIssuerAuthenticationProviderRejectsUnknownIssuer(t *testing.T) {
	provider := authjwt.NewIssuerAuthenticationProvider(
		map[string]authx.TypedAuthenticationProvider[authjwt.TokenCredential]{
			"issuer-a": authjwt.NewProvider(authjwt.WithHMACSecret([]byte("secret"))),
		},
	)
	token := signToken(t, []byte("secret"), jwtlib.SigningMethodHS256, authjwt.Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user-b",
			Issuer:    "issuer-b",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	_, err := provider.AuthenticateAny(context.Background(), authjwt.NewTokenCredential(token))

	assert.Equal(t, authx.ErrorCodeAuthenticationProviderNotFound, authjwt.ClassifyError(err).Code)
}

func TestIssuerAuthenticationProviderRejectsInvalidToken(t *testing.T) {
	provider := authjwt.NewIssuerAuthenticationProvider(
		map[string]authx.TypedAuthenticationProvider[authjwt.TokenCredential]{},
	)

	_, err := provider.AuthenticateAny(context.Background(), authjwt.NewTokenCredential("not-a-jwt"))

	assertJWTErrorCode(t, err, authjwt.ErrorCodeInvalidToken)
}
