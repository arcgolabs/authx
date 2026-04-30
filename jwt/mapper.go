package authjwt

import (
	"context"

	"github.com/arcgolabs/authx"
	collectionlist "github.com/arcgolabs/collectionx/list"
	collectionmapping "github.com/arcgolabs/collectionx/mapping"
)

// PrincipalClaimsMapper maps Claims into authx.Principal using sub/roles/permissions claims.
func PrincipalClaimsMapper(_ context.Context, claims *Claims) (authx.AuthenticationResult, error) {
	if claims == nil || claims.Subject == "" {
		return authx.AuthenticationResult{}, unauthenticatedError(ErrSubjectRequired, "map JWT subject")
	}

	return authx.AuthenticationResult{
		Principal: authx.Principal{
			ID:          claims.Subject,
			Roles:       collectionlist.NewListWithCapacity(len(claims.Roles), claims.Roles...),
			Permissions: collectionlist.NewListWithCapacity(len(claims.Permissions), claims.Permissions...),
			Attributes:  registeredClaimAttributes(claims),
		},
	}, nil
}

func registeredClaimAttributes(claims *Claims) *collectionmapping.Map[string, any] {
	attributes := collectionmapping.NewMap[string, any]()
	if claims.Issuer != "" {
		attributes.Set("issuer", claims.Issuer)
	}
	if len(claims.Audience) > 0 {
		audience := []string(claims.Audience)
		attributes.Set("audience", collectionlist.NewListWithCapacity(len(audience), audience...))
	}
	if claims.ID != "" {
		attributes.Set("jwt_id", claims.ID)
	}
	return attributes
}
