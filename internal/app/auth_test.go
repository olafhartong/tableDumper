package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveAuthMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  authConfig
		want string
	}{
		{
			name: "explicit azcli",
			cfg:  authConfig{AuthMode: "azcli"},
			want: "azcli",
		},
		{
			name: "explicit none",
			cfg:  authConfig{AuthMode: "none"},
			want: "none",
		},
		{
			name: "auto prefers service principal",
			cfg: authConfig{
				AuthMode:     "auto",
				TenantID:     "tenant",
				ClientID:     "client",
				ClientSecret: "secret",
			},
			want: "sp",
		},
		{
			name: "auto falls back to azcli",
			cfg:  authConfig{AuthMode: "auto"},
			want: "azcli",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveAuthMode(tt.cfg); got != tt.want {
				t.Fatalf("resolveAuthMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAcquireTokenNone(t *testing.T) {
	token, mode, err := acquireToken(context.Background(), http.DefaultClient, authConfig{AuthMode: "none"})
	if err != nil {
		t.Fatalf("acquireToken returned error: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token, got %q", token)
	}
	if mode != "none" {
		t.Fatalf("expected none mode, got %q", mode)
	}
}

func TestGetServicePrincipalToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if got := r.URL.Path; got != "/tenant-id/oauth2/token" {
			t.Fatalf("unexpected path %s", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.PostForm.Get("resource"); got != defaultResource {
			t.Fatalf("unexpected resource %q", got)
		}
		if got := r.PostForm.Get("client_id"); got != "client-id" {
			t.Fatalf("unexpected client_id %q", got)
		}
		if got := r.PostForm.Get("client_secret"); got != "secret" {
			t.Fatalf("unexpected client_secret %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"token-value"}`)
	}))
	defer server.Close()

	cfg := config{
		AuthMode:     "sp",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
		Resource:     defaultResource,
		LoginBaseURL: server.URL,
	}

	token, err := getServicePrincipalToken(context.Background(), server.Client(), mdeAuthConfig(cfg))
	if err != nil {
		t.Fatalf("getServicePrincipalToken returned error: %v", err)
	}
	if token != "token-value" {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestParseAzureCLITokenResponse(t *testing.T) {
	token, err := parseAzureCLITokenResponse([]byte(`{"accessToken":"token-value","expiresOn":"2026-09-13 20:00:00.000000","expires_on":1757786400,"tenant":"00000000-0000-0000-0000-000000000000","tokenType":"Bearer"}`))
	if err != nil {
		t.Fatalf("parseAzureCLITokenResponse returned error: %v", err)
	}
	if token != "token-value" {
		t.Fatalf("unexpected token %q", token)
	}

	for _, output := range []string{`{}`, `{"accessToken":""}`, `{"access_token":"token-value"}`} {
		if _, err := parseAzureCLITokenResponse([]byte(output)); err == nil || !strings.Contains(err.Error(), "did not return an access token") {
			t.Fatalf("parseAzureCLITokenResponse(%s) error = %v, want missing token error", output, err)
		}
	}
	if _, err := parseAzureCLITokenResponse([]byte("ERROR: Please run 'az login' to setup account.")); err == nil || !strings.Contains(err.Error(), "decode Azure CLI token response") {
		t.Fatalf("parseAzureCLITokenResponse(non-JSON) error = %v, want decode error", err)
	}
}
