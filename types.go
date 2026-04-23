package authx

import "github.com/arcgolabs/collectionx"

// AuthenticationResult stores identity resolved by authentication.
type AuthenticationResult struct {
	Principal any
	Details   collectionx.Map[string, any]
}

// AuthorizationModel is the transport-agnostic input for authorization.
type AuthorizationModel struct {
	Principal any
	Action    string
	Resource  string
	Context   collectionx.Map[string, any]
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
	Roles       collectionx.List[string]
	Permissions collectionx.List[string]
	Attributes  collectionx.Map[string, any]
}
