package otx

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/bobesa/go-domain-util/domainutil"
	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "otx"
)

type Client struct {
	config *providers.Config
}

var _ providers.Provider = (*Client)(nil)

func New(c *providers.Config) *Client {
	if err := setBaseURL(c.OTX.BaseURL); err != nil {
		logrus.WithField("provider", Name).Warnf("invalid OTX base URL %q: %v; falling back to default", c.OTX.BaseURL, err)
	}
	return &Client{config: c}
}

type otxResult struct {
	HasNext    bool `json:"has_next"`
	ActualSize int  `json:"actual_size"`
	URLList    []struct {
		Domain   string `json:"domain"`
		URL      string `json:"url"`
		Hostname string `json:"hostname"`
		HTTPCode int    `json:"httpcode"`
		PageNum  int    `json:"page_num"`
		FullSize int    `json:"full_size"`
		Paged    bool   `json:"paged"`
	} `json:"url_list"`
}

func (c *Client) Name() string {
	return Name
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	for page := uint(1); ; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page - 1}).Infof("fetching %s", domain)
			apiURL := c.formatURL(domain, page)
			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout, c.headers()...)
			if err != nil {
				return fmt.Errorf("failed to fetch alienvault(%d): %s", page, err)
			}
			var result otxResult
			if err := jsoniter.Unmarshal(resp, &result); err != nil {
				return fmt.Errorf("failed to decode otx results for page %d: %s", page, err)
			}

			for _, entry := range result.URLList {
				results <- entry.URL
			}

			if !result.HasNext {
				return nil
			}
		}
	}
}

func (c *Client) formatURL(domain string, page uint) string {
	category := "hostname"
	if !domainutil.HasSubdomain(domain) {
		category = "domain"
	}
	if domainutil.HasSubdomain(domain) && c.config.IncludeSubdomains {
		domain = domainutil.Domain(domain)
		category = "domain"
	}

	base, err := url.Parse(_BaseURL)
	if err != nil {
		return fmt.Sprintf("%sapi/v1/indicators/%s/%s/url_list?limit=100&page=%d", _BaseURL, category, domain, page)
	}

	base.Path = path.Join(base.Path, "api", "v1", "indicators", category, domain, "url_list")
	query := base.Query()
	query.Set("limit", "100")
	query.Set("page", strconv.FormatUint(uint64(page), 10))
	base.RawQuery = query.Encode()

	return base.String()
}

func (c *Client) headers() []httpclient.Header {
	if c.config.OTX.APIKey == "" {
		return nil
	}

	return []httpclient.Header{{
		Key:   "X-OTX-API-KEY",
		Value: c.config.OTX.APIKey,
	}}
}

const defaultBaseURL = "https://otx.alienvault.com/"

var _BaseURL = defaultBaseURL

func setBaseURL(baseURL string) error {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		_BaseURL = defaultBaseURL
		return nil
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + strings.TrimPrefix(trimmed, "//")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		_BaseURL = defaultBaseURL
		return fmt.Errorf("parse base url: %w", err)
	}

	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	if parsed.Host == "" {
		_BaseURL = defaultBaseURL
		return fmt.Errorf("base url %q missing host", baseURL)
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	} else if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}

	_BaseURL = parsed.String()
	return nil
}
