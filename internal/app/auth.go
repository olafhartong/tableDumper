package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
)

type authConfig struct {
	AuthMode     string
	TenantID     string
	ClientID     string
	ClientSecret string
	Resource     string
	LoginBaseURL string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func acquireToken(ctx context.Context, httpClient *http.Client, cfg authConfig) (token string, authMode string, err error) {
	mode := resolveAuthMode(cfg)

	switch mode {
	case "sp":
		token, err = getServicePrincipalToken(ctx, httpClient, cfg)
	case "azcli":
		token, err = getAzureCLIToken(ctx, cfg)
	default:
		err = fmt.Errorf("internal error: unsupported auth mode %q", mode)
	}

	return token, mode, err
}

func resolveAuthMode(cfg authConfig) string {
	if cfg.AuthMode != "auto" {
		return cfg.AuthMode
	}
	if cfg.TenantID != "" && cfg.ClientID != "" && cfg.ClientSecret != "" {
		return "sp"
	}
	return "azcli"
}

func getServicePrincipalToken(ctx context.Context, httpClient *http.Client, cfg authConfig) (string, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return "", errors.New("service principal auth requires tenant ID, client ID, and client secret")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("resource", cfg.Resource)

	tokenURL := fmt.Sprintf("%s/%s/oauth2/token", cfg.LoginBaseURL, url.PathEscape(cfg.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request service principal token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %s: %s", resp.Status, strings.TrimSpace(compactError(tokenResp.Error, tokenResp.Description, body)))
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token response did not contain an access token")
	}

	return tokenResp.AccessToken, nil
}

func getAzureCLIToken(ctx context.Context, cfg authConfig) (string, error) {
	args := []string{
		"account", "get-access-token",
		"--resource", cfg.Resource,
		"--output", "json",
	}
	if cfg.TenantID != "" {
		args = append(args, "--tenant", cfg.TenantID)
	}

	cmd := exec.CommandContext(ctx, "az", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run Azure CLI token command: %w: %s", err, strings.TrimSpace(string(output)))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(output, &tokenResp); err != nil {
		return "", fmt.Errorf("decode Azure CLI token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("Azure CLI did not return an access token; run 'az login' first")
	}

	return tokenResp.AccessToken, nil
}
