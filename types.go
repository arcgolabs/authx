package authx

import (
	collectionlist "github.com/arcgolabs/collectionx/list"
	collectionmapping "github.com/arcgolabs/collectionx/mapping"
)

// AuthenticationResult stores identity resolved by authentication.
type AuthenticationResult struct {
	Principal any
	Details   *collectionmapping.Map[string, any]
}

// AuthorizationModel is the transport-agnostic input for authorization.
type AuthorizationModel struct {
	Principal any
	Action    string
	Resource  string
	Context   *collectionmapping.Map[string, any]
}

// Decision is the authorization output.
type Decision struct {
	Allowed  bool
	Reason   string
	PolicyID string
}

// Principal is the default identity shape used by built-in helpers.
type Principal struct {
	ID          string
	Roles       *collectionlist.List[string]
	Permissions *collectionlist.List[string]
	Attributes  *collectionmapping.Map[string, any]
}
