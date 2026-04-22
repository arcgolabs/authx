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
	failureHandler func(http.ResponseWriter, *http.Request, int, string)
}

func defaultConfig() config {
	return config{
		failureHandler: writeFailureJSON,
	}
}

// WithFailureHandler overrides the default auth failure writer.
func WithFailureHandler(handler func(http.ResponseWriter, *http.Request, int, string)) Option {
	return func(cfg *config) {
		if handler != nil {
			cfg.failureHandler = handler
		}
	}
}

func writeFailureJSON(w http.ResponseWriter, _ *http.Request, status int, message string) {
	payload, err := json.Marshal(map[string]string{"error": message})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
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
				cfg.failureHandler(w, r, http.StatusInternalServerError, "internal_error")
				return
			}

			result, decision, err := guard.Require(r.Context(), extract(r))
			if err != nil {
				cfg.failureHandler(w, r, authhttp.StatusCodeFromError(err), authhttp.ErrorMessage(err))
				return
			}
			if !decision.Allowed {
				cfg.failureHandler(w, r, http.StatusForbidden, authhttp.DeniedMessage(decision))
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
