// Package safeline is a Go client for the SafeLine (雷池) WAF management
// open API — the /api/* surface documented in the management console's
// openapi_doc handbook. It speaks token authentication (API-Token header)
// and the {err, data, msg} response envelope, and adds typed helpers for
// the protected-site endpoints (FilterV2API, SoftwareReverseProxyWebsiteAPI).
//
// All operations are read-only queries against the management plane.
package safeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client for one SafeLine WAF management API instance.
// It is safe for concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// ClientConfig configures a Client for one WAF instance.
type ClientConfig struct {
	// BaseURL is the management API root, e.g. "https://waf.example.com:9443"
	// (required).
	BaseURL string
	// APIToken is an Open API token created in the management console; it is
	// sent as the API-Token header. May be empty for token-less deployments.
	APIToken string
	// InsecureSkipVerify skips TLS verification (SafeLine defaults to
	// self-signed certificates).
	InsecureSkipVerify bool
	// TimeoutSeconds is the per-request timeout; <= 0 means 30.
	TimeoutSeconds int
}

// NewClient builds a Client for one WAF instance.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("safeline: base_url is required")
	}
	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}},
		},
		token: cfg.APIToken,
	}, nil
}

// envelope is the management API response wrapper. Err is decoded loosely:
// the API returns null on success and a string/object on failure.
type envelope struct {
	Data json.RawMessage `json:"data"`
	Err  any             `json:"err"`
	Msg  string          `json:"msg"`
}

// Get fetches path with query, checks the response envelope, and decodes the
// envelope's data field into result. result may be nil (data discarded) or a
// *json.RawMessage (raw data preserved). Use it to reach endpoints this
// package does not model yet.
func (c *Client) Get(ctx context.Context, path string, query url.Values, result any) error {
	reqURL := c.baseURL + path
	if len(query) > 0 {
		reqURL = reqURL + "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-safeline/0.1")
	if c.token != "" {
		req.Header.Set("API-Token", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, truncate(string(respBody), 512))
	}

	var env envelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		if len(bytes.TrimSpace(respBody)) == 0 {
			return nil
		}
		return fmt.Errorf("unmarshal response: %w (body: %s)", err, truncate(string(respBody), 256))
	}
	if env.Err != nil {
		msg := env.Msg
		if msg == "" {
			msg = fmt.Sprintf("api error: %v", env.Err)
		}
		return fmt.Errorf("%s", msg)
	}

	if result == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, result); err != nil {
		return fmt.Errorf("unmarshal response data: %w (data: %s)", err, truncate(string(env.Data), 256))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
