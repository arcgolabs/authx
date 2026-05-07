//go:build !no_fiber

package fiber

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/gofiber/fiber/v2"
)

// Option configures fiber middleware behavior.
type Option func(*config)

type config struct {
	failureHandler func(*fiber.Ctx, int, string) error
}

func defaultConfig() config {
	return config{
		failureHandler: func(c *fiber.Ctx, status int, message string) error {
			return c.Status(status).JSON(fiber.Map{"error": message})
		},
	}
}

// WithFailureHandler overrides the default auth failure handler.
func WithFailureHandler(handler func(*fiber.Ctx, int, string) error) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.failureHandler = handler
		}
	}
}

// Require runs Check + Can and writes failure response automatically when denied.
func Require(guard *authhttp.Guard, opts ...Option) fiber.Handler {
	return requireWithMode(guard, false, opts...)
}

// RequireFast runs Check + Can with fast request extraction (less copying).
func RequireFast(guard *authhttp.Guard, opts ...Option) fiber.Handler {
	return requireWithMode(guard, true, opts...)
}

func requireWithMode(guard *authhttp.Guard, fast bool, opts ...Option) fiber.Handler {
	cfg := defaultConfig()
	authhttp.ApplyOptions(&cfg, opts...)
	extract := requestInfoFromFiber
	if fast {
		extract = requestInfoFromFiberFast
	}

	return func(c *fiber.Ctx) error {
		if guard == nil {
			return cfg.failureHandler(c, http.StatusInternalServerError, "internal_error")
		}

		ctx := c.UserContext()
		if ctx == nil {
			ctx = context.Background()
		}

		reqInfo := extract(c)
		result, decision, err := guard.Require(ctx, reqInfo)
		if err != nil {
			return cfg.failureHandler(c, authhttp.StatusCodeFromError(err), authhttp.ErrorMessage(err))
		}
		if !decision.Allowed {
			return cfg.failureHandler(c, http.StatusForbidden, authhttp.DeniedMessage(decision))
		}

		c.SetUserContext(authx.WithPrincipal(ctx, result.Principal))
		return c.Next()
	}
}

func requestInfoFromFiberFast(c *fiber.Ctx) authhttp.RequestInfo {
	method, path, pattern, params := requestMetaFromFiber(c)

	return authhttp.RequestInfo{
		Method:       method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      nil,
		Query:        nil,
		PathParams:   params,
		Request:      nil,
		Native:       c,
	}
}

func requestInfoFromFiber(c *fiber.Ctx) authhttp.RequestInfo {
	method, path, pattern, params := requestMetaFromFiber(c)

	return authhttp.RequestInfo{
		Method:       method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      headersFromFiber(c),
		Query:        queryFromFiber(c),
		PathParams:   params,
		Request:      nil,
		Native:       c,
	}
}

func requestMetaFromFiber(c *fiber.Ctx) (method, path, pattern string, params map[string]string) {
	if c == nil {
		return "", "", "", nil
	}

	method = c.Method()
	path = c.Path()
	pattern = path
	if route := c.Route(); route != nil && route.Path != "" {
		pattern = route.Path
		params = pathParamsFromFiberRoute(c, route.Params)
	}

	if shouldInferFiberRoute(pattern, path, params) {
		if inferredPattern, inferredParams, ok := inferFiberRoute(c.App(), method, path); ok {
			pattern = inferredPattern
			params = inferredParams
		}
	}

	return method, path, pattern, params
}

func headersFromFiber(c *fiber.Ctx) http.Header {
	headers := make(http.Header)
	for key, value := range c.Request().Header.All() {
		headers.Add(string(key), string(value))
	}
	return headers
}

func queryFromFiber(c *fiber.Ctx) url.Values {
	if len(c.Request().URI().QueryString()) == 0 {
		return nil
	}

	query := make(url.Values)
	for key, value := range c.Request().URI().QueryArgs().All() {
		query.Add(string(key), string(value))
	}
	return query
}

func pathParamsFromFiberRoute(c *fiber.Ctx, keys []string) map[string]string {
	if c == nil || len(keys) == 0 {
		return nil
	}

	params := make(map[string]string, len(keys))
	for _, key := range keys {
		params[key] = c.Params(key)
	}
	return params
}

func shouldInferFiberRoute(pattern, path string, params map[string]string) bool {
	if len(params) > 0 {
		return false
	}
	return pattern == "" || pattern == "/" || pattern == "/*" || pattern == path
}

func inferFiberRoute(app *fiber.App, method, path string) (string, map[string]string, bool) {
	if app == nil {
		return "", nil, false
	}

	caseSensitive := app.Config().CaseSensitive
	for _, stack := range app.Stack() {
		for _, route := range stack {
			if route == nil || route.Method != method || route.Path == "" || route.Path == "/" || route.Path == "/*" {
				continue
			}
			params, ok := matchFiberRoutePattern(route.Path, path, caseSensitive)
			if ok {
				return route.Path, params, true
			}
		}
	}
	return "", nil, false
}

func matchFiberRoutePattern(pattern, path string, caseSensitive bool) (map[string]string, bool) {
	patternParts := splitFiberPath(pattern)
	pathParts := splitFiberPath(path)
	params := make(map[string]string)

	pathIndex := 0
	for _, part := range patternParts {
		if isFiberWildcardPart(part) {
			name := strings.TrimPrefix(part, "*")
			if name == "" {
				name = "*"
			}
			params[name] = strings.Join(pathParts[pathIndex:], "/")
			return params, true
		}

		optional := strings.HasSuffix(part, "?")
		if strings.HasPrefix(part, ":") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, ":"), "?")
			if pathIndex >= len(pathParts) {
				if optional {
					params[name] = ""
					continue
				}
				return nil, false
			}
			params[name] = pathParts[pathIndex]
			pathIndex++
			continue
		}

		if pathIndex >= len(pathParts) {
			return nil, false
		}
		if !fiberPathPartEqual(part, pathParts[pathIndex], caseSensitive) {
			return nil, false
		}
		pathIndex++
	}

	if pathIndex != len(pathParts) {
		return nil, false
	}
	if len(params) == 0 {
		return nil, true
	}
	return params, true
}

func splitFiberPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func isFiberWildcardPart(part string) bool {
	return part == "*" || strings.HasPrefix(part, "*")
}

func fiberPathPartEqual(left, right string, caseSensitive bool) bool {
	if caseSensitive {
		return left == right
	}
	return strings.EqualFold(left, right)
}
