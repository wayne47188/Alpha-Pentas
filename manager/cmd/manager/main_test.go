package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	newHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "alpha-pentas-manager") {
		t.Fatalf("unexpected response %s", rr.Body.String())
	}
}


func TestOperatorConfigFailsClosedWhenPartiallyConfigured(t *testing.T) {
	t.Setenv("ALPHA_OPERATOR_LISTEN", "127.0.0.1:8443")
	t.Setenv("ALPHA_OPERATOR_TLS_CERT", "")
	t.Setenv("ALPHA_OPERATOR_TLS_KEY", "")
	t.Setenv("ALPHA_OPERATOR_CLIENT_CA", "")
	t.Setenv("ALPHA_DATABASE_URL", "")
	if _, enabled, err := operatorConfigFromEnv(); err == nil || enabled {
		t.Fatalf("partial operator configuration accepted: enabled=%v err=%v", enabled, err)
	}
}

func TestOperatorConfigDisabledWhenUnset(t *testing.T) {
	for _, name := range []string{
		"ALPHA_OPERATOR_LISTEN",
		"ALPHA_OPERATOR_TLS_CERT",
		"ALPHA_OPERATOR_TLS_KEY",
		"ALPHA_OPERATOR_CLIENT_CA",
		"ALPHA_DATABASE_URL",
	} {
		t.Setenv(name, "")
	}
	if _, enabled, err := operatorConfigFromEnv(); err != nil || enabled {
		t.Fatalf("unset operator API should be disabled: enabled=%v err=%v", enabled, err)
	}
}
