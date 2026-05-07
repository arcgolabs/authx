//go:build !no_gin

package gin

import (
	"net/http"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// Option configures gin middleware behavior.
type Option func(*config)

type config struct {
	errorResponseHandler func(*gin.Context, authhttp.ErrorResponse)
}

func defaultConfig() config {
	return config{
		errorResponseHandler: func(c *gin.Context, response authhttp.ErrorResponse) {
			c.AbortWithStatusJSON(response.Status, gin.H{"error": response.Error})
		},
	}
}

// WithFailureHandler overrides the default auth failure handler.
func WithFailureHandler(handler func(*gin.Context, int, string)) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.errorResponseHandler = func(c *gin.Context, response authhttp.ErrorResponse) {
				handler(c, response.Status, response.Error)
			}
		}
	}
}

// WithErrorResponseHandler overrides the default auth failure handler with the full safe response model.
func WithErrorResponseHandler(handler func(*gin.Context, authhttp.ErrorResponse)) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.errorResponseHandler = handler
		}
	}
}

// Require runs Check + Can and aborts request automatically when denied.
func Require(guard *authhttp.Guard, opts ...Option) gin.HandlerFunc {
	return requireWithMode(guard, false, opts...)
}

// RequireFast runs Check + Can with fast request extraction (less copying).
func RequireFast(guard *authhttp.Guard, opts ...Option) gin.HandlerFunc {
	return requireWithMode(guard, true, opts...)
}

func requireWithMode(guard *authhttp.Guard, fast bool, opts ...Option) gin.HandlerFunc {
	cfg := defaultConfig()
	authhttp.ApplyOptions(&cfg, opts...)
	extract := requestInfoFromGin
	if fast {
		extract = requestInfoFromGinFast
	}

	return func(c *gin.Context) {
		if guard == nil {
			cfg.errorResponseHandler(c, authhttp.ErrorResponseFromCode(authx.ErrorCodeNilEngine))
			return
		}

		req := c.Request
		reqInfo := extract(c, req)

		result, decision, err := guard.Require(req.Context(), reqInfo)
		if err != nil {
			cfg.errorResponseHandler(c, authhttp.ErrorResponseFromError(err))
			return
		}
		if !decision.Allowed {
			cfg.errorResponseHandler(c, authhttp.ErrorResponseFromDecision(decision))
			return
		}

		c.Request = req.WithContext(authx.WithPrincipal(req.Context(), result.Principal))
		c.Next()
	}
}

func requestInfoFromGinFast(c *gin.Context, req *http.Request) authhttp.RequestInfo {
	method, path, pattern := requestMetaFromGin(c, req)

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

func requestInfoFromGin(c *gin.Context, req *http.Request) authhttp.RequestInfo {
	method, path, pattern := requestMetaFromGin(c, req)

	var params map[string]string
	if len(c.Params) > 0 {
		params = lo.Associate(c.Params, func(p gin.Param) (string, string) {
			return p.Key, p.Value
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

func requestMetaFromGin(c *gin.Context, req *http.Request) (method, path, pattern string) {
	pattern = c.FullPath()
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
