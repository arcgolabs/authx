//go:build !no_echo

package echo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authhttp "github.com/arcgolabs/authx/http"
	authecho "github.com/arcgolabs/authx/http/echo"
	"github.com/arcgolabs/authx/http/internal/benchmarksupport"
	"github.com/labstack/echo/v4"
)

func BenchmarkRequireCheckCan10kUsers10kPermissions(b *testing.B) {
	runInProcessBench(b, 4041, authecho.Require)
}

func BenchmarkRequireFastCheckCan10kUsers10kPermissions(b *testing.B) {
	runInProcessBench(b, 4043, authecho.RequireFast)
}

func BenchmarkRequireCheckCan10kUsers10kPermissionsRealHTTP(b *testing.B) {
	runRealHTTPBench(b, 4042, authecho.Require)
}

func BenchmarkRequireFastCheckCan10kUsers10kPermissionsRealHTTP(b *testing.B) {
	runRealHTTPBench(b, 4044, authecho.RequireFast)
}

func runInProcessBench(
	b *testing.B,
	seed uint64,
	builder func(*authhttp.Guard, ...authecho.Option) echo.MiddlewareFunc,
) {
	b.Helper()

	dataset := benchmarksupport.NewDataset(seed, 10_000, 10_000, 16, 2_048)
	guard := benchmarksupport.NewGuard(dataset)

	e := echo.New()
	e.Use(builder(guard))
	e.GET("/authz/benchmark", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		query := dataset.Queries[i%len(dataset.Queries)]
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authz/benchmark", http.NoBody)
		req.Header.Set(benchmarksupport.HeaderUserID, query.UserID)
		req.Header.Set(benchmarksupport.HeaderAction, query.Action)
		req.Header.Set(benchmarksupport.HeaderResource, query.Resource)

		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		expectedStatus := http.StatusNoContent
		if !query.Allowed {
			expectedStatus = http.StatusForbidden
		}
		if w.Code != expectedStatus {
			b.Fatalf("unexpected status: got=%d expected=%d", w.Code, expectedStatus)
		}
	}
}

func runRealHTTPBench(
	b *testing.B,
	seed uint64,
	builder func(*authhttp.Guard, ...authecho.Option) echo.MiddlewareFunc,
) {
	b.Helper()

	dataset := benchmarksupport.NewDataset(seed, 10_000, 10_000, 16, 2_048)
	guard := benchmarksupport.NewGuard(dataset)

	e := echo.New()
	e.Use(builder(guard))
	e.GET("/authz/benchmark", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	server := httptest.NewServer(e)
	b.Cleanup(server.Close)

	client := server.Client()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		query := dataset.Queries[i%len(dataset.Queries)]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/authz/benchmark", http.NoBody)
		if err != nil {
			b.Fatalf("create request failed: %v", err)
		}
		req.Header.Set(benchmarksupport.HeaderUserID, query.UserID)
		req.Header.Set(benchmarksupport.HeaderAction, query.Action)
		req.Header.Set(benchmarksupport.HeaderResource, query.Resource)

		resp := doBenchmarkRequest(b, client, req)
		closeResponseBody(b, resp)

		expectedStatus := http.StatusNoContent
		if !query.Allowed {
			expectedStatus = http.StatusForbidden
		}
		if resp.StatusCode != expectedStatus {
			b.Fatalf("unexpected status: got=%d expected=%d", resp.StatusCode, expectedStatus)
		}
	}
}

func doBenchmarkRequest(b *testing.B, client *http.Client, req *http.Request) *http.Response {
	b.Helper()

	//nolint:gosec // Benchmark requests only target the local httptest server created above.
	resp, err := client.Do(req)
	if err != nil {
		b.Fatalf("request failed: %v", err)
	}

	return resp
}

func closeResponseBody(b *testing.B, resp *http.Response) {
	b.Helper()

	if err := resp.Body.Close(); err != nil {
		b.Fatalf("close response body failed: %v", err)
	}
}
