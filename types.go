package safeline

import "encoding/json"

// This file models the WAF management open API shapes verified against a
// live instance: GET /api/FilterV2API (site list) and
// GET /api/SoftwareReverseProxyWebsiteAPI (single site detail). Site objects
// carry many more fields than modeled here; unmodeled fields are ignored by
// the typed helpers — use Client.Get with a *json.RawMessage result when you
// need the complete object.

// ScopeSiteList is the FilterV2API scope value that lists protected sites.
const ScopeSiteList = "detect:asset:site:list"

// SitePort is one listening address of a site (items[].ports / items[].addrs).
type SitePort struct {
	SNI           bool `json:"sni"`
	SSL           bool `json:"ssl"`
	Port          int  `json:"port"`
	HTTP2         bool `json:"http2"`
	NonHTTP       bool `json:"non_http"`
	ProxyProtocol bool `json:"proxy_protocol"`
}

// BackendServer is one upstream origin server (backend_config.servers[]).
type BackendServer struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Weight    int    `json:"weight"`
	Protocol  string `json:"protocol"`
	IsEnabled bool   `json:"is_enabled"`
}

// BackendConfig carries the parts of backend_config used in summaries.
type BackendConfig struct {
	Type              string          `json:"type"`
	Servers           []BackendServer `json:"servers"`
	LoadBalancePolicy string          `json:"load_balance_policy"`
}

// SiteURLPath is one URL-path rule (url_paths[]). Op is the match mode;
// "pre" means path-prefix match.
type SiteURLPath struct {
	Op      string `json:"op"`
	URLPath string `json:"url_path"`
}

// PolicyRuleMeta reads just enough of items[].policy_rules[] to count rules;
// full rule objects are large and only present in raw output.
type PolicyRuleMeta struct {
	ID int64 `json:"id"`
}

// Site is one protected website: a FilterV2API item, or a
// SoftwareReverseProxyWebsiteAPI data object (same shape).
type Site struct {
	ID             int64            `json:"id"`
	Name           string           `json:"name"`
	ServerNames    []string         `json:"server_names"`
	Ports          []SitePort       `json:"ports"`
	Addrs          []SitePort       `json:"addrs"`
	IP             []string         `json:"ip"`
	IsEnabled      bool             `json:"is_enabled"`
	OperationMode  string           `json:"operation_mode"`
	Interface      string           `json:"interface"`
	BackendConfig  BackendConfig    `json:"backend_config"`
	PolicyGroup    int64            `json:"policy_group"`
	AssetGroup     int64            `json:"asset_group"`
	PolicyRules    []PolicyRuleMeta `json:"policy_rules"`
	URLPaths       []SiteURLPath    `json:"url_paths"`
	Remark         string           `json:"remark"`
	CreateTime     string           `json:"create_time"`
	LastUpdateTime string           `json:"last_update_time"`
}

// FilterV2Data is the data payload of GET /api/FilterV2API, with each item
// kept raw so callers can choose between typed decoding and full objects.
type FilterV2Data struct {
	Items []json.RawMessage `json:"items"`
	Total int64             `json:"total"`
}
