package authhttp_test

import (
	"testing"

	authhttp "github.com/arcgolabs/authx/http"
)

type nativeLookupStub struct {
	headers map[string]string
	query   map[string]string
	params  map[string]string
}

func (stub nativeLookupStub) Get(key string, defaultValue ...string) string {
	if value, ok := stub.headers[key]; ok {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func (stub nativeLookupStub) Query(key string, defaultValue ...string) string {
	if value, ok := stub.query[key]; ok {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func (stub nativeLookupStub) Params(key string, defaultValue ...string) string {
	if value, ok := stub.params[key]; ok {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func TestRequestInfoLazyLookupFromNative(t *testing.T) {
	req := authhttp.RequestInfo{
		Native: nativeLookupStub{
			headers: map[string]string{"Authorization": "Bearer token-1"},
			query:   map[string]string{"action": "query"},
			params:  map[string]string{"id": "1001"},
		},
	}

	if got := req.Header("Authorization"); got != "Bearer token-1" {
		t.Fatalf("unexpected header value: %s", got)
	}
	if got := req.QueryValue("action"); got != "query" {
		t.Fatalf("unexpected query value: %s", got)
	}
	if got := req.PathParam("id"); got != "1001" {
		t.Fatalf("unexpected path param value: %s", got)
	}
}
