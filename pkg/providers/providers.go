package providers

import (
	"context"
	"net/url"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/valyala/fasthttp"
)

var Version = `2.2.4`

// Provider is a generic interface for all archive fetchers
type Provider interface {
	Fetch(ctx context.Context, domain string, results chan string) error
	Name() string
}

type URLScan struct {
	Host   string
	APIKey string
}

type OTXConfig struct {
	BaseURL string
	APIKey  string
}

type VirusTotalConfig struct {
	APIKey string
}

type LeakIXConfig struct {
	APIKey string
}

type BraveConfig struct {
	APIKey string
}

type SerpAPIConfig struct {
	APIKey string
}

type FirecrawlConfig struct {
	APIKey string
}

type Config struct {
	Threads           uint
	Timeout           uint
	MaxRetries        uint
	IncludeSubdomains bool
	RemoveParameters  bool
	Client            *fasthttp.Client
	Providers         []string
	Blacklist         mapset.Set[string]
	Output            string
	JSON              bool
	URLScan           URLScan
	OTX               OTXConfig
	VirusTotal        VirusTotalConfig
	LeakIX            LeakIXConfig
	Brave             BraveConfig
	SerpAPI           SerpAPIConfig
	Firecrawl         FirecrawlConfig
}

// MatchesDomain reports whether rawURL belongs to domain. When includeSubdomains
// is false only an exact hostname match passes.
func MatchesDomain(rawURL string, domain string, includeSubdomains bool) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	target := strings.ToLower(strings.TrimSuffix(domain, "."))
	if host == "" || target == "" {
		return false
	}

	if host == target {
		return true
	}

	return includeSubdomains && strings.HasSuffix(host, "."+target)
}
