package echo

import (
	"net/http"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
)

// Option configures echo middleware behavior.
type Option func(*config)

type config struct {
	failureHandler func(echo.Context, int, string) error
}

func defaultConfig() config {
	return config{
		failureHandler: func(c echo.Context, status int, message string) error {
			return c.JSON(status, map[string]string{"error": message})
		},
	}
}

// WithFailureHandler overrides the default auth failure handler.
func WithFailureHandler(handler func(echo.Context, int, string) error) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.failureHandler = handler
		}
	}
}

// Require runs Check + Can and returns failure response automatically when denied.
func Require(guard *authhttp.Guard, opts ...Option) echo.MiddlewareFunc {
	return requireWithMode(guard, false, opts...)
}

// RequireFast runs Check + Can with fast request extraction (less copying).
func RequireFast(guard *authhttp.Guard, opts ...Option) echo.MiddlewareFunc {
	return requireWithMode(guard, true, opts...)
}

func requireWithMode(guard *authhttp.Guard, fast bool, opts ...Option) echo.MiddlewareFunc {
	cfg := defaultConfig()
	authhttp.ApplyOptions(&cfg, opts...)
	extract := requestInfoFromEcho
	if fast {
		extract = requestInfoFromEchoFast
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if guard == nil {
				return cfg.failureHandler(c, http.StatusInternalServerError, "internal_error")
			}

			req := c.Request()
			reqInfo := extract(c, req)

			result, decision, err := guard.Require(req.Context(), reqInfo)
			if err != nil {
				return cfg.failureHandler(c, authhttp.StatusCodeFromError(err), authhttp.ErrorMessage(err))
			}
			if !decision.Allowed {
				return cfg.failureHandler(c, http.StatusForbidden, authhttp.DeniedMessage(decision))
			}

			c.SetRequest(req.WithContext(authx.WithPrincipal(req.Context(), result.Principal)))
			return next(c)
		}
	}
}

func requestInfoFromEchoFast(c echo.Context, req *http.Request) authhttp.RequestInfo {
	method, path, pattern := requestMetaFromEcho(c, req)

	return authhttp.RequestInfo{
		Method:       method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      nil,
		Query:        nil,
		PathParams:   nil,
		Request:      req,
		Native:       c,
	}
}

func requestInfoFromEcho(c echo.Context, req *http.Request) authhttp.RequestInfo {
	method, path, pattern := requestMetaFromEcho(c, req)

	paramNames := c.ParamNames()
	var params map[string]string
	if len(paramNames) > 0 {
		params = lo.Associate(paramNames, func(name string) (string, string) {
			return name, c.Param(name)
		})
	}

	var headers http.Header
	var query map[string][]string
	if req != nil {
		headers, query = clonedRequestData(req)
	}

	return authhttp.RequestInfo{
		Method:       method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      headers,
		Query:        query,
		PathParams:   params,
		Request:      req,
		Native:       c,
	}
}

func requestMetaFromEcho(c echo.Context, req *http.Request) (method, path, pattern string) {
	pattern = c.Path()
	if req != nil {
		method = req.Method
		if req.URL != nil {
			path = req.URL.Path
		}
	}
	if pattern == "" {
		pattern = path
	}
	return method, path, pattern
}

func clonedRequestData(req *http.Request) (http.Header, map[string][]string) {
	if req == nil {
		return nil, nil
	}

	headers := req.Header.Clone()
	if req.URL == nil || req.URL.RawQuery == "" {
		return headers, nil
	}

	return headers, req.URL.Query()
}
