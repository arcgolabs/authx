package shared

import (
	"strings"

	collectionlist "github.com/arcgolabs/collectionx/list"
)

// ParseBearer extracts a bearer token from an Authorization header value.
func ParseBearer(raw string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, token != ""
}

// HasRole reports whether roles contains target.
func HasRole(roles *collectionlist.List[string], target string) bool {
	if roles == nil {
		return false
	}
	return roles.AnyMatch(func(_ int, role string) bool {
		return role == target
	})
}
