package authx

import (
	"context"
	"strings"

	collectionlist "github.com/arcgolabs/collectionx/list"
)

const (
	// PolicyRequireRole identifies decisions produced by role-based helpers.
	PolicyRequireRole = "authx.require_role"
	// PolicyRequirePermission identifies decisions produced by permission-based helpers.
	PolicyRequirePermission = "authx.require_permission"

	// ReasonInvalidPrincipal indicates that the principal is not an authx.Principal.
	ReasonInvalidPrincipal = "invalid_principal"
	// ReasonRoleRequired indicates that none of the required roles was present.
	ReasonRoleRequired = "role_required"
	// ReasonPermissionRequired indicates that none of the required permissions was present.
	ReasonPermissionRequired = "permission_required"
)

// PrincipalFromAny returns the default Principal from either Principal or *Principal.
func PrincipalFromAny(input any) (Principal, bool) {
	switch principal := input.(type) {
	case Principal:
		return principal, true
	case *Principal:
		if principal == nil {
			return Principal{}, false
		}
		return *principal, true
	default:
		return Principal{}, false
	}
}

// HasRole reports whether the principal contains role.
func HasRole(principal any, role string) bool {
	return HasAnyRole(principal, role)
}

// HasAnyRole reports whether the principal contains at least one role.
func HasAnyRole(principal any, roles ...string) bool {
	typed, ok := PrincipalFromAny(principal)
	if !ok {
		return false
	}
	return listContainsAny(typed.Roles, roles...)
}

// HasPermission reports whether the principal contains permission.
func HasPermission(principal any, permission string) bool {
	return HasAnyPermission(principal, permission)
}

// HasAnyPermission reports whether the principal contains at least one permission.
func HasAnyPermission(principal any, permissions ...string) bool {
	typed, ok := PrincipalFromAny(principal)
	if !ok {
		return false
	}
	return listContainsAny(typed.Permissions, permissions...)
}

// RequireRole allows authorization when the principal contains role.
func RequireRole(role string) Authorizer {
	return RequireAnyRole(role)
}

// RequireAnyRole allows authorization when the principal contains at least one role.
func RequireAnyRole(roles ...string) Authorizer {
	required := normalizedStrings(roles...)
	return AuthorizerFunc(func(_ context.Context, input AuthorizationModel) (Decision, error) {
		return requireAnyPrincipalValue(input.Principal, required, inputHasRole, PolicyRequireRole, ReasonRoleRequired), nil
	})
}

// RequirePermission allows authorization when the principal contains permission.
func RequirePermission(permission string) Authorizer {
	return RequireAnyPermission(permission)
}

// RequireAnyPermission allows authorization when the principal contains at least one permission.
func RequireAnyPermission(permissions ...string) Authorizer {
	required := normalizedStrings(permissions...)
	return AuthorizerFunc(func(_ context.Context, input AuthorizationModel) (Decision, error) {
		return requireAnyPrincipalValue(
			input.Principal,
			required,
			inputHasPermission,
			PolicyRequirePermission,
			ReasonPermissionRequired,
		), nil
	})
}

func requireAnyPrincipalValue(
	principal any,
	required []string,
	matches func(Principal, []string) bool,
	policyID string,
	missingReason string,
) Decision {
	typed, ok := PrincipalFromAny(principal)
	if !ok {
		return Decision{Allowed: false, Reason: ReasonInvalidPrincipal, PolicyID: policyID}
	}
	if len(required) == 0 || !matches(typed, required) {
		return Decision{Allowed: false, Reason: missingReason, PolicyID: policyID}
	}
	return Decision{Allowed: true, PolicyID: policyID}
}

func inputHasRole(principal Principal, required []string) bool {
	return listContainsAny(principal.Roles, required...)
}

func inputHasPermission(principal Principal, required []string) bool {
	return listContainsAny(principal.Permissions, required...)
}

func listContainsAny(values *collectionlist.List[string], candidates ...string) bool {
	if values == nil {
		return false
	}

	required := normalizedStringSet(candidates...)
	if len(required) == 0 {
		return false
	}

	return values.AnyMatch(func(_ int, value string) bool {
		_, ok := required[strings.TrimSpace(value)]
		return ok
	})
}

func normalizedStrings(values ...string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func normalizedStringSet(values ...string) map[string]struct{} {
	normalized := normalizedStrings(values...)
	if len(normalized) == 0 {
		return nil
	}

	out := make(map[string]struct{}, len(normalized))
	for _, value := range normalized {
		out[value] = struct{}{}
	}
	return out
}
