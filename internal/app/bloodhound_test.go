package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadFileToBloodHound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.opengraph.json")
	if err := os.WriteFile(path, []byte(`{"graph":{"nodes":[],"edges":[]}}`), 0o600); err != nil {
		t.Fatalf("write graph file: %v", err)
	}

	var startCalls int
	var endCalls int
	var uploadCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			startCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("unexpected auth header %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"id":42}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42":
			uploadCalls++
			if got := r.Header.Get("X-File-Upload-Name"); got != "graph.opengraph.json" {
				t.Fatalf("unexpected upload filename %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("unexpected content type %q", got)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read upload body: %v", err)
			}
			if string(body) != `{"graph":{"nodes":[],"edges":[]}}` {
				t.Fatalf("unexpected upload body %s", string(body))
			}
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42/end":
			endCalls++
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"id":42}}`)
		default:
			t.Fatalf("unexpected path %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		BloodHoundURL:   server.URL,
		BloodHoundToken: "test-token",
	}

	jobID, err := uploadFileToBloodHound(context.Background(), server.Client(), cfg, path)
	if err != nil {
		t.Fatalf("uploadFileToBloodHound returned error: %v", err)
	}
	if jobID != 42 {
		t.Fatalf("unexpected job id %d", jobID)
	}
	if startCalls != 1 || uploadCalls != 1 || endCalls != 1 {
		t.Fatalf("unexpected call counts start=%d upload=%d end=%d", startCalls, uploadCalls, endCalls)
	}
}

func TestUploadCustomNodesToBloodHound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.opengraph.icons.json")
	payload := openGraphCustomNodePayload{
		CustomTypes: map[string]openGraphCustomNodeConfig{
			"Machine": {Icon: openGraphCustomNodeIcon{Type: "font-awesome", Name: "desktop", Color: "#2563EB"}},
			"User":    {Icon: openGraphCustomNodeIcon{Type: "font-awesome", Name: "user", Color: "#16A34A"}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal icon payload: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write icon file: %v", err)
	}

	var createBody openGraphCustomNodePayload
	var updateBody bloodHoundCustomNodeUpdateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/custom-nodes":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[{"kindName":"User","config":{"icon":{"type":"font-awesome","name":"user"}}}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/custom-nodes":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{}}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v2/custom-nodes/User":
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatalf("decode update body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{}}`)
		default:
			t.Fatalf("unexpected path %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		BloodHoundURL:   server.URL,
		BloodHoundToken: "test-token",
	}

	created, updated, err := uploadCustomNodesToBloodHound(context.Background(), server.Client(), cfg, path)
	if err != nil {
		t.Fatalf("uploadCustomNodesToBloodHound returned error: %v", err)
	}
	if created != 1 || updated != 1 {
		t.Fatalf("unexpected create/update counts %d/%d", created, updated)
	}
	if _, ok := createBody.CustomTypes["Machine"]; !ok {
		t.Fatalf("expected Machine in create payload %#v", createBody)
	}
	if updateBody.Config.Icon.Name != "user" {
		t.Fatalf("unexpected update payload %#v", updateBody)
	}
}

func TestAuthorizeBloodHoundRequestWithSignedAuth(t *testing.T) {
	cfg := config{
		BloodHoundTokenID:  "token-id",
		BloodHoundTokenKey: base64.StdEncoding.EncodeToString([]byte("super-secret-key")),
	}
	body := []byte(`{"graph":{"nodes":[],"edges":[]}}`)

	req, err := http.NewRequest(http.MethodPost, "https://bloodhound.example/api/v2/file-upload/42", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		t.Fatalf("authorizeBloodHoundRequest returned error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "bhesignature token-id" {
		t.Fatalf("unexpected authorization header %q", got)
	}
	if req.Header.Get("RequestDate") == "" {
		t.Fatalf("expected request date header")
	}
	wantSig, err := buildBloodHoundRequestSignature(cfg.BloodHoundTokenKey, req.Header.Get("RequestDate"), http.MethodPost, "/api/v2/file-upload/42", body)
	if err != nil {
		t.Fatalf("buildBloodHoundRequestSignature returned error: %v", err)
	}
	if got := req.Header.Get("Signature"); got != wantSig {
		t.Fatalf("unexpected signature %q want %q", got, wantSig)
	}
}
