package authjwt

import (
	"context"
	"strings"

	"github.com/arcgolabs/authx"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// NewIssuerAuthenticationProvider selects a JWT provider by the unverified iss claim.
//
// The selected provider still performs full signature and claims validation.
func NewIssuerAuthenticationProvider(
	providers map[string]authx.TypedAuthenticationProvider[TokenCredential],
) authx.AuthenticationProvider {
	return authx.NewKeyedSelectorAuthenticationProvider(selectIssuer, providers)
}

func selectIssuer(_ context.Context, credential TokenCredential) (string, error) {
	tokenString := strings.TrimSpace(credential.Token)
	if tokenString == "" {
		return "", newError(ErrorCodeTokenEmpty, "validate JWT credential")
	}

	claims := &Claims{}
	_, _, err := jwtlib.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return "", wrapError(err, ErrorCodeInvalidToken, "parse JWT issuer")
	}
	issuer := strings.TrimSpace(claims.Issuer)
	if issuer == "" {
		return "", newError(ErrorCodeIssuerRequired, "resolve JWT issuer")
	}
	return issuer, nil
}
