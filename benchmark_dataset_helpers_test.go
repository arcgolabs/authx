package authx_test

import (
	"fmt"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
)

func samplePermission(randSource *gofakeit.Faker, assigned map[string]struct{}) string {
	target := randSource.Number(0, len(assigned)-1)
	for permission := range assigned {
		if target == 0 {
			return permission
		}
		target--
	}
	return ""
}

func permissionKey(action, resource string) string {
	return action + "|" + resource
}

func parsePermissionKey(key string) (string, string) {
	action, resource, found := strings.Cut(key, "|")
	if !found {
		return key, ""
	}
	return action, resource
}

func normalizeFakeToken(raw string) string {
	token := strings.ToLower(strings.TrimSpace(raw))
	token = strings.ReplaceAll(token, " ", "_")
	token = strings.ReplaceAll(token, "-", "_")
	if token == "" {
		return "x"
	}
	return token
}

func buildBenchmarkPermissions(randSource *gofakeit.Faker, permissionCount int) []string {
	permissions := make([]string, permissionCount)
	for i := range permissionCount {
		action := fmt.Sprintf("%s-%03d", normalizeFakeToken(randSource.Verb()), i/100)
		resource := fmt.Sprintf("%s-%03d", normalizeFakeToken(randSource.Noun()), i%100)
		permissions[i] = permissionKey(action, resource)
	}
	return permissions
}

func buildBenchmarkUsers(
	randSource *gofakeit.Faker,
	userCount int,
	permissionsPerUser int,
	permissions []string,
) ([]string, map[string]map[string]struct{}) {
	userIDs := make([]string, userCount)
	userPermissions := make(map[string]map[string]struct{}, userCount)
	for i := range userCount {
		userID := fmt.Sprintf("%s-%05d", normalizeFakeToken(randSource.Username()), i)
		userIDs[i] = userID
		userPermissions[userID] = pickAssignedPermissions(randSource, permissionsPerUser, permissions)
	}
	return userIDs, userPermissions
}

func pickAssignedPermissions(
	randSource *gofakeit.Faker,
	permissionsPerUser int,
	permissions []string,
) map[string]struct{} {
	assigned := make(map[string]struct{}, permissionsPerUser)
	for len(assigned) < permissionsPerUser {
		assigned[permissions[randSource.Number(0, len(permissions)-1)]] = struct{}{}
	}
	return assigned
}

func buildBenchmarkQueries(
	randSource *gofakeit.Faker,
	userIDs []string,
	userPermissions map[string]map[string]struct{},
	permissions []string,
	queryCount int,
) []benchmarkDatasetQuery {
	queries := make([]benchmarkDatasetQuery, queryCount)
	for i := range queryCount {
		queries[i] = buildBenchmarkQuery(randSource, userIDs, userPermissions, permissions, i)
	}
	return queries
}

func buildBenchmarkQuery(
	randSource *gofakeit.Faker,
	userIDs []string,
	userPermissions map[string]map[string]struct{},
	permissions []string,
	index int,
) benchmarkDatasetQuery {
	userID := userIDs[randSource.Number(0, len(userIDs)-1)]
	assigned := userPermissions[userID]
	permission, allowed := selectBenchmarkPermission(randSource, assigned, permissions, index)
	action, resource := parsePermissionKey(permission)

	return benchmarkDatasetQuery{
		userID:   userID,
		action:   action,
		resource: resource,
		allowed:  allowed,
	}
}

func selectBenchmarkPermission(
	randSource *gofakeit.Faker,
	assigned map[string]struct{},
	permissions []string,
	index int,
) (string, bool) {
	permission := samplePermission(randSource, assigned)
	if index%2 == 0 {
		return permission, true
	}

	for {
		candidate := permissions[randSource.Number(0, len(permissions)-1)]
		if _, exists := assigned[candidate]; !exists {
			return candidate, false
		}
	}
}
