package authjwt

import "github.com/golang-jwt/jwt/v5"

// TokenCredential is the transport-neutral credential handled by Provider.
type TokenCredential struct {
	Token string
}

// NewTokenCredential creates a TokenCredential from a raw JWT token string.
func NewTokenCredential(token string) TokenCredential {
	return TokenCredential{Token: token}
}

// Claims is the default JWT claims shape mapped by PrincipalClaimsMapper.
// Slice fields are kept here to match JWT JSON unmarshalling and are converted
// to list.List values by the mapper.
type Claims struct {
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}
