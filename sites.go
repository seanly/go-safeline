package safeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotFound is returned by GetSiteDetail when the requested site id does
// not exist. Test for it with errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("safeline: site not found")

// ListSitesOptions are the parameters of Client.ListSites.
type ListSitesOptions struct {
	// Count is the page size (number of sites to return); <= 0 means 20.
	Count int
	// Offset is the pagination offset into the result set; negative clamps to 0.
	Offset int
	// ServerName optionally filters to one domain: exact case-insensitive
	// match (maps to the server_names__iexact query parameter).
	ServerName string
	// Scope is the FilterV2API scope; empty means ScopeSiteList. Override only
	// if you know the API supports another scope.
	Scope string
}

// Query renders the options as FilterV2API query parameters, applying
// defaults (count 20, offset 0, scope detect:asset:site:list).
func (o ListSitesOptions) Query() url.Values {
	count := o.Count
	if count <= 0 {
		count = 20
	}
	offset := o.Offset
	if offset < 0 {
		offset = 0
	}
	scope := o.Scope
	if scope == "" {
		scope = ScopeSiteList
	}
	q := url.Values{}
	q.Set("count", strconv.Itoa(count))
	q.Set("offset", strconv.Itoa(offset))
	q.Set("scope", scope)
	if o.ServerName != "" {
		q.Set("server_names__iexact", o.ServerName)
	}
	return q
}

// SitesPage is one page of ListSites results.
type SitesPage struct {
	Sites []Site
	Total int64
}

// ListSites lists protected websites via GET /api/FilterV2API. Filter keys
// follow the API's Django-style __-suffix conventions (server_names__iexact
// for a case-insensitive exact match). See ListSitesOptions for the knobs.
func (c *Client) ListSites(ctx context.Context, opts ListSitesOptions) (*SitesPage, error) {
	var data FilterV2Data
	if err := c.Get(ctx, "/api/FilterV2API", opts.Query(), &data); err != nil {
		return nil, fmt.Errorf("list sites: %w", err)
	}
	sites := make([]Site, 0, len(data.Items))
	for _, raw := range data.Items {
		var s Site
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("parse site object: %w", err)
		}
		sites = append(sites, s)
	}
	return &SitesPage{Sites: sites, Total: data.Total}, nil
}

// GetSiteDetail returns one full site object via
// GET /api/SoftwareReverseProxyWebsiteAPI?id=. The returned Site carries the
// modeled fields; fetch the endpoint through Client.Get with a
// *json.RawMessage result if you need unmodeled fields verbatim. Returns
// ErrNotFound when the id does not exist.
func (c *Client) GetSiteDetail(ctx context.Context, id int64) (*Site, error) {
	q := url.Values{}
	q.Set("id", strconv.FormatInt(id, 10))

	var raw json.RawMessage
	if err := c.Get(ctx, "/api/SoftwareReverseProxyWebsiteAPI", q, &raw); err != nil {
		return nil, fmt.Errorf("get site detail: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, ErrNotFound
	}
	var s Site
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse site object: %w", err)
	}
	return &s, nil
}

// SiteSummary is the compact per-site view produced by SummarizeSite.
type SiteSummary struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name,omitempty"`
	ServerNames     []string `json:"server_names"`
	IsEnabled       bool     `json:"is_enabled"`
	OperationMode   string   `json:"operation_mode,omitempty"`
	Interface       string   `json:"interface,omitempty"`
	ListenPorts     []string `json:"listen_ports,omitempty"`
	BindIPs         []string `json:"bind_ips,omitempty"`
	Upstreams       []string `json:"upstreams,omitempty"`
	URLPaths        []string `json:"url_paths"`
	LoadBalance     string   `json:"load_balance_policy,omitempty"`
	PolicyRuleCount int      `json:"policy_rule_count"`
	PolicyGroup     int64    `json:"policy_group,omitempty"`
	AssetGroup      int64    `json:"asset_group,omitempty"`
	Remark          string   `json:"remark,omitempty"`
	CreateTime      string   `json:"create_time,omitempty"`
	LastUpdateTime  string   `json:"last_update_time,omitempty"`
}

// SummarizeSite reduces one site to its operational essentials.
// create_time / last_update_time are epoch-seconds strings, passed through.
// url_paths rules render as "<op> <path>" ("pre" = path prefix); an empty
// array means the site has no path restriction.
func SummarizeSite(s Site) SiteSummary {
	sum := SiteSummary{
		ID:              s.ID,
		Name:            s.Name,
		ServerNames:     s.ServerNames,
		IsEnabled:       s.IsEnabled,
		OperationMode:   s.OperationMode,
		Interface:       s.Interface,
		BindIPs:         s.IP,
		LoadBalance:     s.BackendConfig.LoadBalancePolicy,
		PolicyRuleCount: len(s.PolicyRules),
		PolicyGroup:     s.PolicyGroup,
		AssetGroup:      s.AssetGroup,
		URLPaths:        []string{},
		Remark:          s.Remark,
		CreateTime:      s.CreateTime,
		LastUpdateTime:  s.LastUpdateTime,
	}
	if sum.ServerNames == nil {
		sum.ServerNames = []string{}
	}
	seen := map[int]bool{}
	for _, p := range s.Ports {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		sum.ListenPorts = append(sum.ListenPorts, describePort(p))
	}
	for _, srv := range s.BackendConfig.Servers {
		sum.Upstreams = append(sum.Upstreams, describeUpstream(srv))
	}
	for _, up := range s.URLPaths {
		sum.URLPaths = append(sum.URLPaths, describeURLPath(up))
	}
	return sum
}

// describePort renders one listening port compactly, e.g. "80" or "443 ssl".
func describePort(p SitePort) string {
	var tags []string
	if p.SSL {
		tags = append(tags, "ssl")
	}
	if p.NonHTTP {
		tags = append(tags, "non-http")
	}
	if p.ProxyProtocol {
		tags = append(tags, "proxy-protocol")
	}
	if len(tags) == 0 {
		return strconv.Itoa(p.Port)
	}
	return strconv.Itoa(p.Port) + " " + strings.Join(tags, "+")
}

// describeUpstream renders one origin server, e.g. "http://10.184.22.33:80".
func describeUpstream(srv BackendServer) string {
	addr := srv.Host + ":" + strconv.Itoa(srv.Port)
	if srv.Protocol == "" {
		return addr
	}
	return srv.Protocol + "://" + addr
}

// describeURLPath renders one url_paths rule compactly, e.g. "pre /api/x/y"
// (op is the match mode, "pre" = path prefix).
func describeURLPath(up SiteURLPath) string {
	if up.Op == "" {
		return up.URLPath
	}
	return up.Op + " " + up.URLPath
}
