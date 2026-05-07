package std

import (
	"encoding/json"
	"net/http"

	"github.com/arcgolabs/authx"
	authhttp "github.com/arcgolabs/authx/http"
)

// Option configures std middleware behavior.
type Option func(*config)

type config struct {
	errorResponseWriter func(http.ResponseWriter, *http.Request, authhttp.ErrorResponse)
}

func defaultConfig() config {
	return config{
		errorResponseWriter: writeFailureJSON,
	}
}

// WithFailureHandler overrides the default auth failure writer.
func WithFailureHandler(handler func(http.ResponseWriter, *http.Request, int, string)) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.errorResponseWriter = func(w http.ResponseWriter, r *http.Request, response authhttp.ErrorResponse) {
				handler(w, r, response.Status, response.Error)
			}
		}
	}
}

// WithErrorResponseWriter overrides the default auth failure writer with the full safe response model.
func WithErrorResponseWriter(writer func(http.ResponseWriter, *http.Request, authhttp.ErrorResponse)) Option {
	return func(cfg *config) {
		if writer != nil {
			cfg.errorResponseWriter = writer
		}
	}
}

func writeFailureJSON(w http.ResponseWriter, _ *http.Request, response authhttp.ErrorResponse) {
	payload, err := json.Marshal(map[string]string{"error": response.Error})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.Status)
	if _, err = w.Write(payload); err != nil {
		return
	}
}

// Require runs Check + Can and writes failure response automatically.
func Require(guard *authhttp.Guard, opts ...Option) func(http.Handler) http.Handler {
	return requireWithMode(guard, false, opts...)
}

// RequireFast runs Check + Can with fast request extraction (less copying).
func RequireFast(guard *authhttp.Guard, opts ...Option) func(http.Handler) http.Handler {
	return requireWithMode(guard, true, opts...)
}

func requireWithMode(guard *authhttp.Guard, fast bool, opts ...Option) func(http.Handler) http.Handler {
	cfg := defaultConfig()
	authhttp.ApplyOptions(&cfg, opts...)
	extract := requestInfoExtractor(fast)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if guard == nil {
				cfg.errorResponseWriter(w, r, authhttp.ErrorResponseFromCode(authx.ErrorCodeNilEngine))
				return
			}

			result, decision, err := guard.Require(r.Context(), extract(r))
			if err != nil {
				cfg.errorResponseWriter(w, r, authhttp.ErrorResponseFromError(err))
				return
			}
			if !decision.Allowed {
				cfg.errorResponseWriter(w, r, authhttp.ErrorResponseFromDecision(decision))
				return
			}

			next.ServeHTTP(w, r.WithContext(authx.WithPrincipal(r.Context(), result.Principal)))
		})
	}
}

func requestInfoExtractor(fast bool) func(*http.Request) authhttp.RequestInfo {
	if fast {
		return requestInfoFromStdFast
	}
	return requestInfoFromStd
}
