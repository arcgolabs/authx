package std

import (
	"net/http"

	authhttp "github.com/arcgolabs/authx/http"
	"github.com/go-chi/chi/v5"
)

func requestInfoFromStd(r *http.Request) authhttp.RequestInfo {
	reqInfo := authhttp.RequestInfoFromHTTPRequest(r)
	return applyCHIRouteMeta(r, reqInfo)
}

func requestInfoFromStdFast(r *http.Request) authhttp.RequestInfo {
	reqInfo := authhttp.RequestInfoFromHTTPRequestFast(r)
	return applyCHIRouteMeta(r, reqInfo)
}

func applyCHIRouteMeta(r *http.Request, reqInfo authhttp.RequestInfo) authhttp.RequestInfo {
	if r == nil {
		return reqInfo
	}

	routeCtx := chi.RouteContext(r.Context())
	if routeCtx == nil {
		return reqInfo
	}

	pattern, params := chiRouteMeta(r, routeCtx)
	if pattern != "" {
		reqInfo.RoutePattern = pattern
	}
	if len(params) > 0 {
		reqInfo.PathParams = params
	}

	return reqInfo
}

func chiRouteMeta(r *http.Request, routeCtx *chi.Context) (string, map[string]string) {
	if routeCtx == nil {
		return "", nil
	}

	if pattern := routeCtx.RoutePattern(); pattern != "" {
		return pattern, chiPathParams(routeCtx)
	}
	if routeCtx.Routes == nil {
		return "", nil
	}

	method := routeCtx.RouteMethod
	if method == "" && r != nil {
		method = r.Method
	}

	matchCtx := chi.NewRouteContext()
	if !routeCtx.Routes.Match(matchCtx, method, requestPath(r, routeCtx)) {
		return "", nil
	}

	return matchCtx.RoutePattern(), chiPathParams(matchCtx)
}

func requestPath(r *http.Request, routeCtx *chi.Context) string {
	if routeCtx != nil && routeCtx.RoutePath != "" {
		return routeCtx.RoutePath
	}
	if r == nil || r.URL == nil {
		return "/"
	}
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	if r.URL.Path != "" {
		return r.URL.Path
	}
	return "/"
}

func chiPathParams(routeCtx *chi.Context) map[string]string {
	if routeCtx == nil || len(routeCtx.URLParams.Keys) == 0 {
		return nil
	}

	params := make(map[string]string, len(routeCtx.URLParams.Keys))
	for i, key := range routeCtx.URLParams.Keys {
		if i < len(routeCtx.URLParams.Values) {
			params[key] = routeCtx.URLParams.Values[i]
		}
	}
	return params
}
