package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
