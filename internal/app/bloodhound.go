package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type bloodHoundFileUploadJobResponse struct {
	Data struct {
		ID int64 `json:"id"`
	} `json:"data"`
}

type bloodHoundCustomNodeListResponse struct {
	Data []bloodHoundCustomNode `json:"data"`
}

type bloodHoundCustomNode struct {
	KindName string                    `json:"kindName"`
	Config   openGraphCustomNodeConfig `json:"config"`
}

type bloodHoundCustomNodeUpdateRequest struct {
	Config openGraphCustomNodeConfig `json:"config"`
}

func uploadFileToBloodHound(ctx context.Context, httpClient *http.Client, cfg config, path string) (int64, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read BloodHound upload file %s: %w", path, err)
	}

	jobID, err := startBloodHoundFileUploadJob(ctx, httpClient, cfg)
	if err != nil {
		return 0, err
	}
	if err := sendBloodHoundFileUpload(ctx, httpClient, cfg, jobID, path, body); err != nil {
		return 0, err
	}
	if err := endBloodHoundFileUploadJob(ctx, httpClient, cfg, jobID); err != nil {
		return 0, err
	}
	return jobID, nil
}

func startBloodHoundFileUploadJob(ctx context.Context, httpClient *http.Client, cfg config) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BloodHoundURL+"/api/v2/file-upload/start", nil)
	if err != nil {
		return 0, fmt.Errorf("build BloodHound file upload start request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return 0, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("start BloodHound file upload job: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read BloodHound file upload start response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("BloodHound file upload start failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed bloodHoundFileUploadJobResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("decode BloodHound file upload start response: %w", err)
	}
	if parsed.Data.ID == 0 {
		return 0, errors.New("BloodHound file upload start response did not contain a job id")
	}
	return parsed.Data.ID, nil
}

func sendBloodHoundFileUpload(ctx context.Context, httpClient *http.Client, cfg config, jobID int64, path string, body []byte) error {
	uploadURL := fmt.Sprintf("%s/api/v2/file-upload/%d", cfg.BloodHoundURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound file upload request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", bloodHoundUploadContentType(path))
	req.Header.Set("X-File-Upload-Name", filepath.Base(path))

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload file %s to BloodHound: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound file upload response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound file upload failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func endBloodHoundFileUploadJob(ctx context.Context, httpClient *http.Client, cfg config, jobID int64) error {
	endURL := fmt.Sprintf("%s/api/v2/file-upload/%d/end", cfg.BloodHoundURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endURL, nil)
	if err != nil {
		return fmt.Errorf("build BloodHound file upload end request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("end BloodHound file upload job %d: %w", jobID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound file upload end response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound file upload end failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func uploadCustomNodesToBloodHound(ctx context.Context, httpClient *http.Client, cfg config, path string) (int, int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read BloodHound icon file %s: %w", path, err)
	}

	var payload openGraphCustomNodePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0, fmt.Errorf("decode BloodHound icon file %s: %w", path, err)
	}
	if len(payload.CustomTypes) == 0 {
		return 0, 0, errors.New("BloodHound icon file did not contain any custom_types")
	}

	existing, err := getBloodHoundCustomNodeKinds(ctx, httpClient, cfg)
	if err != nil {
		return 0, 0, err
	}

	toCreate := openGraphCustomNodePayload{CustomTypes: make(map[string]openGraphCustomNodeConfig)}
	toUpdate := make(map[string]openGraphCustomNodeConfig)
	for kind, config := range payload.CustomTypes {
		if existing[kind] {
			toUpdate[kind] = config
			continue
		}
		toCreate.CustomTypes[kind] = config
	}

	if len(toCreate.CustomTypes) > 0 {
		if err := createBloodHoundCustomNodes(ctx, httpClient, cfg, toCreate); err != nil {
			return 0, 0, err
		}
	}

	kinds := make([]string, 0, len(toUpdate))
	for kind := range toUpdate {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		if err := updateBloodHoundCustomNode(ctx, httpClient, cfg, kind, toUpdate[kind]); err != nil {
			return 0, 0, err
		}
	}

	return len(toCreate.CustomTypes), len(toUpdate), nil
}

func getBloodHoundCustomNodeKinds(ctx context.Context, httpClient *http.Client, cfg config) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BloodHoundURL+"/api/v2/custom-nodes", nil)
	if err != nil {
		return nil, fmt.Errorf("build BloodHound custom node list request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list BloodHound custom nodes: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read BloodHound custom node list response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("BloodHound custom node list failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed bloodHoundCustomNodeListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode BloodHound custom node list response: %w", err)
	}

	result := make(map[string]bool, len(parsed.Data))
	for _, node := range parsed.Data {
		if strings.TrimSpace(node.KindName) != "" {
			result[node.KindName] = true
		}
	}
	return result, nil
}

func createBloodHoundCustomNodes(ctx context.Context, httpClient *http.Client, cfg config, payload openGraphCustomNodePayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode BloodHound custom node create payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BloodHoundURL+"/api/v2/custom-nodes", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound custom node create request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create BloodHound custom nodes: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound custom node create response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound custom node create failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func updateBloodHoundCustomNode(ctx context.Context, httpClient *http.Client, cfg config, kind string, customConfig openGraphCustomNodeConfig) error {
	body, err := json.Marshal(bloodHoundCustomNodeUpdateRequest{Config: customConfig})
	if err != nil {
		return fmt.Errorf("encode BloodHound custom node update payload: %w", err)
	}

	updateURL := fmt.Sprintf("%s/api/v2/custom-nodes/%s", cfg.BloodHoundURL, url.PathEscape(kind))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, updateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound custom node update request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update BloodHound custom node %s: %w", kind, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound custom node update response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound custom node update failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func setBloodHoundAuthHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func bloodHoundUploadContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return "application/zip"
	default:
		return "application/json"
	}
}

func authorizeBloodHoundRequest(req *http.Request, cfg config, body []byte) error {
	setBloodHoundAuthHeaders(req, cfg.BloodHoundToken)
	if strings.TrimSpace(cfg.BloodHoundToken) != "" {
		return nil
	}
	if strings.TrimSpace(cfg.BloodHoundTokenID) == "" || strings.TrimSpace(cfg.BloodHoundTokenKey) == "" {
		return errors.New("missing BloodHound authentication credentials")
	}

	requestDate := time.Now().UTC().Format(time.RFC3339)
	signature, err := buildBloodHoundRequestSignature(cfg.BloodHoundTokenKey, requestDate, req.Method, req.URL.RequestURI(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("bhesignature %s", cfg.BloodHoundTokenID))
	req.Header.Set("RequestDate", requestDate)
	req.Header.Set("Signature", signature)
	return nil
}

func buildBloodHoundRequestSignature(tokenKey, requestDate, method, requestURI string, body []byte) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(tokenKey)
	if err != nil {
		return "", fmt.Errorf("decode BloodHound token key: %w", err)
	}

	operationKey := computeHMACSHA256(keyBytes, []byte(strings.ToUpper(method)+requestURI))
	dateKey := computeHMACSHA256(operationKey, []byte(requestDate))
	bodyKey := computeHMACSHA256(dateKey, body)
	return base64.StdEncoding.EncodeToString(bodyKey), nil
}

func computeHMACSHA256(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
}
