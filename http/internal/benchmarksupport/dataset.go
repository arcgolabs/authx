package benchmarksupport

import (
	"fmt"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/samber/lo"
)

// Query describes one benchmark authorization lookup.
type Query struct {
	UserID   string
	Action   string
	Resource string
	Allowed  bool
}

// Dataset holds generated users, permissions, and benchmark queries.
type Dataset struct {
	userPermissions map[string]map[string]struct{}
	Queries         []Query
}

// NewDataset generates a synthetic benchmark dataset.
func NewDataset(
	seed uint64,
	userCount int,
	permissionCount int,
	permissionsPerUser int,
	queryCount int,
) Dataset {
	randSource := gofakeit.New(seed)
	permissions := buildPermissions(randSource, permissionCount)
	userIDs, userPermissions := buildUsers(randSource, userCount, permissionsPerUser, permissions)
	queries := buildQueries(randSource, userIDs, userPermissions, permissions, queryCount)

	return Dataset{
		userPermissions: userPermissions,
		Queries:         queries,
	}
}

// IsAllowed reports whether userID is allowed to access action/resource.
func (dataset Dataset) IsAllowed(userID, action, resource string) bool {
	permissions, ok := dataset.userPermissions[userID]
	if !ok {
		return false
	}
	_, allowed := permissions[permissionKey(action, resource)]
	return allowed
}

// HasUser reports whether userID exists in the generated dataset.
func (dataset Dataset) HasUser(userID string) bool {
	_, ok := dataset.userPermissions[userID]
	return ok
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

func normalizeFakeToken(raw string) string {
	token := strings.ToLower(strings.TrimSpace(raw))
	token = strings.ReplaceAll(token, " ", "_")
	token = strings.ReplaceAll(token, "-", "_")
	if token == "" {
		return "x"
	}
	return token
}

func buildPermissions(randSource *gofakeit.Faker, permissionCount int) []string {
	return lo.Map(lo.Range(permissionCount), func(i int, _ int) string {
		action := fmt.Sprintf("%s-%03d", normalizeFakeToken(randSource.Verb()), i/100)
		resource := fmt.Sprintf("%s-%03d", normalizeFakeToken(randSource.Noun()), i%100)
		return permissionKey(action, resource)
	})
}

func buildUsers(
	randSource *gofakeit.Faker,
	userCount int,
	permissionsPerUser int,
	permissions []string,
) ([]string, map[string]map[string]struct{}) {
	userIDs := lo.Map(lo.Range(userCount), func(i int, _ int) string {
		return fmt.Sprintf("%s-%05d", normalizeFakeToken(randSource.Username()), i)
	})
	userPermissions := lo.Associate(userIDs, func(userID string) (string, map[string]struct{}) {
		return userID, assignPermissions(randSource, permissionsPerUser, permissions)
	})
	return userIDs, userPermissions
}

func assignPermissions(
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

func buildQueries(
	randSource *gofakeit.Faker,
	userIDs []string,
	userPermissions map[string]map[string]struct{},
	permissions []string,
	queryCount int,
) []Query {
	return lo.Map(lo.Range(queryCount), func(i int, _ int) Query {
		return buildQuery(randSource, userIDs, userPermissions, permissions, i)
	})
}

func buildQuery(
	randSource *gofakeit.Faker,
	userIDs []string,
	userPermissions map[string]map[string]struct{},
	permissions []string,
	index int,
) Query {
	userID := userIDs[randSource.Number(0, len(userIDs)-1)]
	assigned := userPermissions[userID]
	permission, allowed := selectPermission(randSource, assigned, permissions, index)
	action, resource := parsePermissionKey(permission)

	return Query{
		UserID:   userID,
		Action:   action,
		Resource: resource,
		Allowed:  allowed,
	}
}

func selectPermission(
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
