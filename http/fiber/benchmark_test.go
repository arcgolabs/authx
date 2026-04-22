//go:build !no_fiber

package fiber_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authhttp "github.com/arcgolabs/authx/http"
	authfiber "github.com/arcgolabs/authx/http/fiber"
	"github.com/arcgolabs/authx/http/internal/benchmarksupport"
	"github.com/gofiber/fiber/v2"
)

func BenchmarkRequireCheckCan10kUsers10kPermissions(b *testing.B) {
	runInProcessBench(b, 5051, authfiber.Require)
}

func BenchmarkRequireFastCheckCan10kUsers10kPermissions(b *testing.B) {
	runInProcessBench(b, 5053, authfiber.RequireFast)
}

func BenchmarkRequireCheckCan10kUsers10kPermissionsRealHTTP(b *testing.B) {
	runRealHTTPBench(b, 5052, authfiber.Require)
}

func BenchmarkRequireFastCheckCan10kUsers10kPermissionsRealHTTP(b *testing.B) {
	runRealHTTPBench(b, 5054, authfiber.RequireFast)
}

func runInProcessBench(
	b *testing.B,
	seed uint64,
	builder func(*authhttp.Guard, ...authfiber.Option) fiber.Handler,
) {
	b.Helper()

	dataset := benchmarksupport.NewDataset(seed, 10_000, 10_000, 16, 2_048)
	guard := benchmarksupport.NewGuard(dataset)

	app := newBenchmarkApp(guard, builder)

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		query := dataset.Queries[i%len(dataset.Queries)]
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authz/benchmark", http.NoBody)
		req.Header.Set(benchmarksupport.HeaderUserID, query.UserID)
		req.Header.Set(benchmarksupport.HeaderAction, query.Action)
		req.Header.Set(benchmarksupport.HeaderResource, query.Resource)

		resp, err := app.Test(req, -1)
		if err != nil {
			b.Fatalf("request failed: %v", err)
		}
		closeResponseBody(b, resp)

		assertBenchmarkStatus(b, resp.StatusCode, query.Allowed)
	}
}

func runRealHTTPBench(
	b *testing.B,
	seed uint64,
	builder func(*authhttp.Guard, ...authfiber.Option) fiber.Handler,
) {
	b.Helper()

	dataset := benchmarksupport.NewDataset(seed, 10_000, 10_000, 16, 2_048)
	guard := benchmarksupport.NewGuard(dataset)
	baseURL := startBenchmarkServer(b, guard, builder)
	client := newBenchmarkClient(2 * time.Second)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		query := dataset.Queries[i%len(dataset.Queries)]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, benchmarkURL(baseURL), http.NoBody)
		if err != nil {
			b.Fatalf("create request failed: %v", err)
		}
		req.Header.Set(benchmarksupport.HeaderUserID, query.UserID)
		req.Header.Set(benchmarksupport.HeaderAction, query.Action)
		req.Header.Set(benchmarksupport.HeaderResource, query.Resource)

		resp := doBenchmarkRequest(b, client, req)
		closeResponseBody(b, resp)

		assertBenchmarkStatus(b, resp.StatusCode, query.Allowed)
	}
}

func waitForFiberReady(b *testing.B, baseURL string) {
	b.Helper()

	client := newBenchmarkClient(300 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, benchmarkURL(baseURL), http.NoBody)
		if err != nil {
			b.Fatalf("create readiness request failed: %v", err)
		}
		req.Header.Set(benchmarksupport.HeaderUserID, "warmup")
		req.Header.Set(benchmarksupport.HeaderAction, "warmup")
		req.Header.Set(benchmarksupport.HeaderResource, "warmup")

		resp, err := doBenchmarkRequestE(client, req)
		if err == nil {
			closeResponseBody(b, resp)
			return
		}

		time.Sleep(25 * time.Millisecond)
	}

	b.Fatal("fiber server readiness timeout")
}

func newBenchmarkApp(
	guard *authhttp.Guard,
	builder func(*authhttp.Guard, ...authfiber.Option) fiber.Handler,
) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(builder(guard))
	app.Get("/authz/benchmark", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})
	return app
}

func startBenchmarkServer(
	b *testing.B,
	guard *authhttp.Guard,
	builder func(*authhttp.Guard, ...authfiber.Option) fiber.Handler,
) string {
	b.Helper()

	app := newBenchmarkApp(guard, builder)
	listener := listenLoopback(b)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- app.Listener(listener)
	}()

	b.Cleanup(func() {
		shutdownBenchmarkServer(b, app, serverErr)
	})

	baseURL := "http://" + listener.Addr().String()
	waitForFiberReady(b, baseURL)
	return baseURL
}

func listenLoopback(b *testing.B) net.Listener {
	b.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen failed: %v", err)
	}

	return listener
}

func shutdownBenchmarkServer(b *testing.B, app *fiber.App, serverErr <-chan error) {
	b.Helper()

	if err := app.Shutdown(); err != nil {
		b.Fatalf("shutdown fiber app failed: %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			b.Fatalf("fiber server failed: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

func newBenchmarkClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func benchmarkURL(baseURL string) string {
	return baseURL + "/authz/benchmark"
}

func doBenchmarkRequest(b *testing.B, client *http.Client, req *http.Request) *http.Response {
	b.Helper()

	resp, err := doBenchmarkRequestE(client, req)
	if err != nil {
		b.Fatalf("request failed: %v", err)
	}

	return resp
}

func doBenchmarkRequestE(client *http.Client, req *http.Request) (*http.Response, error) {
	//nolint:gosec // Benchmark requests only target loopback listeners created inside the test.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform benchmark request: %w", err)
	}
	return resp, nil
}

func closeResponseBody(b *testing.B, resp *http.Response) {
	b.Helper()

	if err := resp.Body.Close(); err != nil {
		b.Fatalf("close response body failed: %v", err)
	}
}

func assertBenchmarkStatus(b *testing.B, statusCode int, allowed bool) {
	b.Helper()

	expectedStatus := http.StatusNoContent
	if !allowed {
		expectedStatus = http.StatusForbidden
	}
	if statusCode != expectedStatus {
		b.Fatalf("unexpected status: got=%d expected=%d", statusCode, expectedStatus)
	}
}
