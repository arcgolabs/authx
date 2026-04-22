package authhttp

import (
	"context"
	"maps"
	"net/http"
	"net/url"
)

type routePatternContextKey struct{}
type pathParamsContextKey struct{}

// RequestInfo is the normalized HTTP request shape used by auth middleware.
type RequestInfo struct {
	Method       string
	Path         string
	RoutePattern string
	Headers      http.Header
	Query        url.Values
	PathParams   map[string]string
	Request      *http.Request
	Native       any
}

type nativeHeaderGetter interface {
	Get(key string, defaultValue ...string) string
}

type nativeQueryGetter interface {
	Query(key string, defaultValue ...string) string
}

type nativePathParamGetter interface {
	Params(key string, defaultValue ...string) string
}

type nativeParamGetter interface {
	Param(key string) string
}

// Header returns request header value from fast available source.
func (req RequestInfo) Header(key string) string {
	if req.Headers != nil {
		return req.Headers.Get(key)
	}
	if req.Request != nil {
		return req.Request.Header.Get(key)
	}
	if native, ok := req.Native.(nativeHeaderGetter); ok {
		return native.Get(key)
	}
	return ""
}

// QueryValue returns query parameter value from fast available source.
func (req RequestInfo) QueryValue(key string) string {
	if req.Query != nil {
		return req.Query.Get(key)
	}
	if req.Request != nil && req.Request.URL != nil && req.Request.URL.RawQuery != "" {
		return req.Request.URL.Query().Get(key)
	}
	if native, ok := req.Native.(nativeQueryGetter); ok {
		return native.Query(key)
	}
	return ""
}

// PathParam returns path parameter value from fast available source.
func (req RequestInfo) PathParam(key string) string {
	if req.PathParams != nil {
		return req.PathParams[key]
	}
	if native, ok := req.Native.(nativePathParamGetter); ok {
		return native.Params(key)
	}
	if native, ok := req.Native.(nativeParamGetter); ok {
		return native.Param(key)
	}
	return ""
}

// WithRoutePattern stores a route template (for example "/orders/:id") on context.
func WithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, routePatternContextKey{}, pattern)
}

// RoutePatternFromContext returns route template from context.
func RoutePatternFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	pattern, ok := ctx.Value(routePatternContextKey{}).(string)
	if !ok || pattern == "" {
		return "", false
	}
	return pattern, true
}

// WithPathParams stores normalized route params on context.
func WithPathParams(ctx context.Context, params map[string]string) context.Context {
	if len(params) == 0 {
		return ctx
	}
	return context.WithValue(ctx, pathParamsContextKey{}, cloneStringMap(params))
}

// PathParamsFromContext returns route params from context.
func PathParamsFromContext(ctx context.Context) (map[string]string, bool) {
	params, ok := pathParamsFromContextView(ctx)
	if !ok || len(params) == 0 {
		return nil, false
	}
	return cloneStringMap(params), true
}

// RequestInfoFromHTTPRequest builds RequestInfo from standard *http.Request.
func RequestInfoFromHTTPRequest(r *http.Request) RequestInfo {
	if r == nil {
		return RequestInfo{}
	}

	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}

	pattern, ok := RoutePatternFromContext(r.Context())
	if !ok {
		pattern = path
	}

	pathParams, _ := PathParamsFromContext(r.Context())
	return RequestInfo{
		Method:       r.Method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      r.Header.Clone(),
		Query:        queryValuesFromURL(r.URL),
		PathParams:   pathParams,
		Request:      r,
	}
}

// RequestInfoFromHTTPRequestFast builds RequestInfo with minimal copying for hot paths.
// The returned Headers and PathParams share underlying data with request/context values.
func RequestInfoFromHTTPRequestFast(r *http.Request) RequestInfo {
	if r == nil {
		return RequestInfo{}
	}

	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}

	pattern, ok := RoutePatternFromContext(r.Context())
	if !ok {
		pattern = path
	}

	pathParams, _ := pathParamsFromContextView(r.Context())
	return RequestInfo{
		Method:       r.Method,
		Path:         path,
		RoutePattern: pattern,
		Headers:      r.Header,
		Query:        nil,
		PathParams:   pathParams,
		Request:      r,
	}
}

func pathParamsFromContextView(ctx context.Context) (map[string]string, bool) {
	if ctx == nil {
		return nil, false
	}
	params, ok := ctx.Value(pathParamsContextKey{}).(map[string]string)
	if !ok || len(params) == 0 {
		return nil, false
	}
	return params, true
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	return maps.Clone(in)
}

func queryValuesFromURL(uri *url.URL) url.Values {
	if uri == nil || uri.RawQuery == "" {
		return nil
	}
	return uri.Query()
}
