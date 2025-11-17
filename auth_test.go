package traefik_gssapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freddo3000/traefik-gssapi"
)

func TestAuth(t *testing.T) {
	cfg := traefik_gssapi.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := traefik_gssapi.New(ctx, next, cfg, "gss-auth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status code: %d", recorder.Code)
	}
	if recorder.Header().Get("Www-Authenticate") != "Negotiate" {
		t.Fatalf("unexpected header value: %s", recorder.Header().Get("Www-Authenticate"))
	}
}
