package shared

import (
	"net/http"

	authhttp "github.com/arcgolabs/authx/http"
	"github.com/go-chi/chi/v5"
)

// CHIRouteMetaMiddleware injects chi route metadata into the authx request context.
func CHIRouteMetaMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeCtx := chi.RouteContext(r.Context())
		if routeCtx != nil {
			ctx := authhttp.WithRoutePattern(r.Context(), routeCtx.RoutePattern())
			r = r.WithContext(authhttp.WithPathParams(ctx, chiPathParams(routeCtx)))
		}
		next.ServeHTTP(w, r)
	})
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
