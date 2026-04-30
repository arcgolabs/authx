package shared

import (
	"errors"
	"sort"
	"strings"

	collectionlist "github.com/arcgolabs/collectionx/list"
	collectionmapping "github.com/arcgolabs/collectionx/mapping"
)

// MethodActionResolver maps HTTP methods to auth action names.
type MethodActionResolver struct {
	actionByMethod *collectionmapping.Map[string, string]
}

// NewMethodActionResolver creates a method-to-action resolver.
func NewMethodActionResolver(actionByMethod map[string]string) MethodActionResolver {
	normalized := make(map[string]string, len(actionByMethod))
	for rawKey, rawValue := range actionByMethod {
		key := strings.ToUpper(strings.TrimSpace(rawKey))
		value := strings.TrimSpace(rawValue)
		if key != "" && value != "" {
			normalized[key] = value
		}
	}

	return MethodActionResolver{
		actionByMethod: collectionmapping.NewMapFrom(normalized),
	}
}

// Resolve maps an HTTP method to an action name.
func (resolver MethodActionResolver) Resolve(method string) (string, error) {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	if action, ok := resolver.actionByMethod.Get(normalizedMethod); ok {
		return action, nil
	}
	return "", errors.New("unsupported method for action mapping")
}

// RouteResourceResolver maps route patterns to auth resource names.
type RouteResourceResolver struct {
	resourceByExactPattern *collectionmapping.Map[string, string]
	resourceByPrefix       *collectionmapping.Map[string, string]
}

// NewRouteResourceResolver creates a route-to-resource resolver.
func NewRouteResourceResolver(
	resourceByExactPattern map[string]string,
	resourceByPrefix map[string]string,
) RouteResourceResolver {
	return RouteResourceResolver{
		resourceByExactPattern: collectionmapping.NewMapFrom(normalizedEntries(resourceByExactPattern)),
		resourceByPrefix:       collectionmapping.NewMapFrom(normalizedEntries(resourceByPrefix)),
	}
}

// Resolve maps a route pattern to a resource name.
func (resolver RouteResourceResolver) Resolve(routePattern string) (string, error) {
	pattern := strings.TrimSpace(routePattern)
	if pattern == "" {
		return "", errors.New("empty route pattern")
	}

	if resource, ok := resolver.resourceByExactPattern.Get(pattern); ok {
		return resource, nil
	}

	prefixes := resolver.resourceByPrefix.Keys()
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})
	if prefix, found := collectionlist.NewList(prefixes...).FirstWhere(func(_ int, p string) bool {
		return strings.HasPrefix(pattern, p)
	}).Get(); found {
		if resource, ok := resolver.resourceByPrefix.Get(prefix); ok {
			return resource, nil
		}
	}

	return "", errors.New("unsupported route pattern for resource mapping")
}

func normalizedEntries(entries map[string]string) map[string]string {
	if len(entries) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(entries))
	for rawKey, rawValue := range entries {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key != "" && value != "" {
			normalized[key] = value
		}
	}

	return normalized
}
