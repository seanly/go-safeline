package safeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestNewClient_RequiresBaseURL(t *testing.T) {
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Fatalf("expected error for empty base_url")
	}
	if _, err := NewClient(ClientConfig{BaseURL: "  "}); err == nil {
		t.Fatalf("expected error for blank base_url")
	}
	c, err := NewClient(ClientConfig{BaseURL: "https://waf:9443/"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.baseURL != "https://waf:9443" {
		t.Errorf("baseURL = %q, want trailing slash trimmed", c.baseURL)
	}
}

func TestListSitesOptions_Query(t *testing.T) {
	// Defaults.
	q := ListSitesOptions{}.Query()
	want := url.Values{
		"count":  {"20"},
		"offset": {"0"},
		"scope":  {ScopeSiteList},
	}
	if !reflect.DeepEqual(q, want) {
		t.Errorf("query = %v, want %v", q, want)
	}

	// Explicit values + domain filter; negative offset clamps to zero.
	q = ListSitesOptions{Count: 5, Offset: -3, ServerName: "app.example.com"}.Query()
	if q.Get("server_names__iexact") != "app.example.com" {
		t.Errorf("server_names__iexact = %q", q.Get("server_names__iexact"))
	}
	if q.Get("count") != "5" || q.Get("offset") != "0" {
		t.Errorf("count/offset = %q/%q, want 5/0", q.Get("count"), q.Get("offset"))
	}

	// Scope override passes through.
	q = ListSitesOptions{Scope: "some:other:scope"}.Query()
	if q.Get("scope") != "some:other:scope" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
}

// sampleSite is a trimmed-but-shape-faithful FilterV2API item captured from
// the live API (site 498).
const sampleSite = `{
	"id": 498,
	"ip": ["0.0.0.0", "::"],
	"policy_rules": [
		{"id": 102, "action": "deny", "is_enabled": true, "comment": "仅开放/fin/export/bohai/"}
	],
	"backend_config": {
		"type": "proxy",
		"servers": [
			{"host": "10.184.22.33", "port": 80, "weight": 1, "protocol": "http", "is_enabled": true}
		],
		"keepalive": 32,
		"load_balance_policy": "Round Robin"
	},
	"server_names": ["app.example.com"],
	"ports": [
		{"sni": false, "ssl": false, "port": 80, "http2": false, "non_http": false, "proxy_protocol": false}
	],
	"is_enabled": true,
	"name": "app.example.com|生产|支付中心(payment-center",
	"operation_mode": "Software Reverse Proxy",
	"interface": "virtual",
	"policy_group": 3,
	"asset_group": 13,
	"remark": "https://devops.example.com/system/deliver/application/detail?id=7772",
	"create_time": "1768292899",
	"last_update_time": "1768292996",
	"url_paths": [{"op": "pre", "url_path": "/"}]
}`

func TestSummarizeSite(t *testing.T) {
	var s Site
	if err := json.Unmarshal([]byte(sampleSite), &s); err != nil {
		t.Fatalf("unmarshal sampleSite: %v", err)
	}
	sum := SummarizeSite(s)
	if sum.ID != 498 {
		t.Errorf("id = %d, want 498", sum.ID)
	}
	if !reflect.DeepEqual(sum.ServerNames, []string{"app.example.com"}) {
		t.Errorf("server_names = %v", sum.ServerNames)
	}
	if !sum.IsEnabled {
		t.Errorf("is_enabled = false, want true")
	}
	if !reflect.DeepEqual(sum.ListenPorts, []string{"80"}) {
		t.Errorf("listen_ports = %v, want [80]", sum.ListenPorts)
	}
	if !reflect.DeepEqual(sum.Upstreams, []string{"http://10.184.22.33:80"}) {
		t.Errorf("upstreams = %v", sum.Upstreams)
	}
	if !reflect.DeepEqual(sum.URLPaths, []string{"pre /"}) {
		t.Errorf("url_paths = %v, want [pre /]", sum.URLPaths)
	}
	if sum.PolicyRuleCount != 1 {
		t.Errorf("policy_rule_count = %d, want 1", sum.PolicyRuleCount)
	}
	if sum.OperationMode != "Software Reverse Proxy" {
		t.Errorf("operation_mode = %q", sum.OperationMode)
	}
	if sum.LoadBalance != "Round Robin" {
		t.Errorf("load_balance_policy = %q", sum.LoadBalance)
	}
	if sum.CreateTime != "1768292899" {
		t.Errorf("create_time = %q", sum.CreateTime)
	}
}

func TestSummarizeSite_SSLPortTagAndEmptyURLPaths(t *testing.T) {
	s := Site{
		ID:          1,
		ServerNames: []string{"a.com"},
		Ports: []SitePort{
			{SNI: true, SSL: true, Port: 443, HTTP2: true},
			{Port: 443, NonHTTP: true},
		},
	}
	sum := SummarizeSite(s)
	// Duplicate port 443 collapses to one entry; the ssl variant wins (first seen).
	if !reflect.DeepEqual(sum.ListenPorts, []string{"443 ssl"}) {
		t.Errorf("listen_ports = %v, want [443 ssl]", sum.ListenPorts)
	}
	// No url_paths configured → empty array, not null.
	if !reflect.DeepEqual(sum.URLPaths, []string{}) {
		t.Errorf("url_paths = %v, want []", sum.URLPaths)
	}
	if !reflect.DeepEqual(sum.ServerNames, []string{"a.com"}) {
		t.Errorf("server_names = %v", sum.ServerNames)
	}
}

// newTestClient serves handler under /api/ and returns a client pointed at it.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURL: srv.URL, APIToken: "tok-test", TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestListSites(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("API-Token"); got != "tok-test" {
			t.Errorf("API-Token header = %q, want tok-test", got)
		}
		if r.URL.Path != "/api/FilterV2API" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("scope") != ScopeSiteList || q.Get("count") != "20" {
			t.Errorf("query = %v", q)
		}
		fmt.Fprintf(w, `{"err": null, "msg": null, "data": {"items": [%s], "total": 1}}`, sampleSite)
	})

	page, err := c.ListSites(context.Background(), ListSitesOptions{})
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if page.Total != 1 || len(page.Sites) != 1 {
		t.Fatalf("total=%d sites=%d, want 1/1", page.Total, len(page.Sites))
	}
	if page.Sites[0].ID != 498 {
		t.Errorf("site id = %d, want 498", page.Sites[0].ID)
	}
	if !reflect.DeepEqual(page.Sites[0].URLPaths, []SiteURLPath{{Op: "pre", URLPath: "/"}}) {
		t.Errorf("url_paths = %v", page.Sites[0].URLPaths)
	}
}

// TestListSites_RawItemsKeepsUnmodeledFields guards the FilterV2Data raw-item
// contract that full-object consumers rely on.
func TestListSites_RawItemsKeepsUnmodeledFields(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"err": null, "data": {"items": [%s], "total": 1}}`, sampleSite)
	})
	var data FilterV2Data
	if err := c.Get(context.Background(), "/api/FilterV2API", ListSitesOptions{}.Query(), &data); err != nil {
		t.Fatalf("Get: %v", err)
	}
	var item map[string]any
	if err := json.Unmarshal(data.Items[0], &item); err != nil {
		t.Fatalf("unmarshal item: %v", err)
	}
	if _, ok := item["backend_config"].(map[string]any)["keepalive"]; !ok {
		t.Errorf("unmodeled field keepalive lost from raw item")
	}
}

func TestGetSiteDetail(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/SoftwareReverseProxyWebsiteAPI" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("id") != "498" {
			t.Errorf("id = %q", r.URL.Query().Get("id"))
		}
		fmt.Fprintf(w, `{"err": null, "data": %s, "msg": null}`, sampleSite)
	})
	s, err := c.GetSiteDetail(context.Background(), 498)
	if err != nil {
		t.Fatalf("GetSiteDetail: %v", err)
	}
	if s.ID != 498 || s.Name != "app.example.com|生产|支付中心(payment-center" {
		t.Errorf("site = %d/%q", s.ID, s.Name)
	}
}

func TestGetSiteDetail_NotFound(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"err": null, "data": null, "msg": null}`))
	})
	_, err := c.GetSiteDetail(context.Background(), 498)
	if err == nil {
		t.Fatalf("expected error for null data")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestClientEnvelopeError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"err": "permission denied", "msg": "无权访问该接口", "data": null}`))
	})
	err := c.Get(context.Background(), "/api/FilterV2API", nil, nil)
	if err == nil {
		t.Fatalf("expected envelope error, got nil")
	}
	if !strings.Contains(err.Error(), "无权访问该接口") {
		t.Errorf("error = %v, want msg from envelope", err)
	}
}

func TestClientHTTPError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`boom`))
	})
	err := c.Get(context.Background(), "/api/SoftwareReverseProxyWebsiteAPI", url.Values{"id": {"498"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want status 500 failure", err)
	}
}
