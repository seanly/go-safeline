# go-safeline

Go client library for the [SafeLine WAF (雷池)](https://github.com/chaitin/SafeLine) management open API — the `/api/*` surface documented in the management console's `openapi_doc` handbook.

It speaks token authentication (the `API-Token` header) and the `{err, data, msg}` response envelope, and adds typed helpers for the protected-site endpoints. No CLI, no MCP server, no plugin runtime — just a library you import.

```bash
go get github.com/seanly/go-safeline
```

All operations are **read-only** queries against the management plane.

## Usage

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	safeline "github.com/seanly/go-safeline"
)

func main() {
	client, err := safeline.NewClient(safeline.ClientConfig{
		BaseURL:            "https://waf.example.com:9443",
		APIToken:           os.Getenv("SAFELINE_API_TOKEN"),
		InsecureSkipVerify: true, // SafeLine defaults to self-signed certs
	})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	// List protected sites (GET /api/FilterV2API), optionally filtered by domain.
	page, err := client.ListSites(ctx, safeline.ListSitesOptions{
		ServerName: "app.example.com", // maps to server_names__iexact
	})
	if err != nil {
		panic(err)
	}
	for _, site := range page.Sites {
		sum := safeline.SummarizeSite(site) // compact operational view
		fmt.Println(sum.ID, sum.ServerNames, sum.ListenPorts, sum.Upstreams, sum.URLPaths)
	}

	// One full site config (GET /api/SoftwareReverseProxyWebsiteAPI?id=).
	site, err := client.GetSiteDetail(ctx, 498)
	if errors.Is(err, safeline.ErrNotFound) {
		fmt.Println("no such site")
	}
}
```

## API

| Symbol | Purpose |
|--------|---------|
| `NewClient(ClientConfig)` | Build a client for one WAF instance (base URL, token, TLS, timeout) |
| `Client.ListSites(ctx, ListSitesOptions)` | `GET /api/FilterV2API` → `*SitesPage` (`[]Site` + `Total`), pagination count/offset |
| `Client.GetSiteDetail(ctx, id)` | `GET /api/SoftwareReverseProxyWebsiteAPI?id=` → `*Site`; returns `ErrNotFound` for unknown ids |
| `Client.Get(ctx, path, query, &result)` | Envelope-generic access to any other `/api/*` endpoint this package does not model yet |
| `SummarizeSite(Site) SiteSummary` | Compact view: listen ports, upstreams, `url_paths` (`"pre /path"`), policy counts, … |
| `ListSitesOptions.Query()` | Render list options as FilterV2API query parameters (with defaults applied) |

`Site` models the commonly used fields (server names, ports, backend/upstream config, `url_paths`, policy groups, timestamps). Site objects carry more fields than modeled; pass a `*json.RawMessage` result to `Client.Get` when you need unmodeled fields verbatim.

`create_time` / `last_update_time` are epoch-seconds strings, passed through as-is.

## Authentication

Create a token in the management console: avatar (top right) → 个人中心 → Open API. Tokens carry their own permissions — keep them minimal (read-only), and set IP source / expiry limits where possible.

## Verified endpoints

- `GET /api/FilterV2API?count&offset&scope=detect:asset:site:list[&server_names__iexact=]`
- `GET /api/SoftwareReverseProxyWebsiteAPI?id=`

Used by [dmr-plugin-safeline](https://github.com/seanly/dmr-plugin-safeline), which exposes this library to DMR agents as read-only WAF-query tools.
