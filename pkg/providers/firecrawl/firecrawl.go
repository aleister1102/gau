package firecrawl

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "firecrawl"
)

var _ providers.Provider = (*Client)(nil)

var (
	rateMu   sync.Mutex
	lastCall time.Time
)

type Client struct {
	config *providers.Config
}

func New(c *providers.Config) *Client {
	return &Client{config: c}
}

func (c *Client) Name() string {
	return Name
}

type mapResponse struct {
	Success bool                  `json:"success"`
	Links   []jsoniter.RawMessage `json:"links"`
	Error   string                `json:"error"`
}

type linkObject struct {
	URL string `json:"url"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if c.config.Firecrawl.APIKey == "" {
		logrus.WithField("provider", Name).Debug("no firecrawl apikey provided, skipping")
		return nil
	}

	select {
	case <-ctx.Done():
		return nil
	default:
		waitForRateLimit()
		logrus.WithFields(logrus.Fields{"provider": Name}).Infof("fetching %s", domain)

		payload := map[string]any{
			"url":                   "https://" + domain,
			"limit":                 5000,
			"includeSubdomains":     c.config.IncludeSubdomains,
			"ignoreQueryParameters": false,
			"sitemap":               "include",
		}
		body, err := jsoniter.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to encode firecrawl request: %s", err)
		}

		header := httpclient.Header{
			Key:   "Authorization",
			Value: "Bearer " + c.config.Firecrawl.APIKey,
		}
		accept := httpclient.Header{
			Key:   "Accept",
			Value: "application/json",
		}

		timeout := c.config.Timeout
		if timeout < 120 {
			timeout = 120
		}

		resp, err := httpclient.MakeJSONRequest(c.config.Client, "https://api.firecrawl.dev/v2/map", body, c.config.MaxRetries, timeout, header, accept)
		if err != nil {
			return fmt.Errorf("failed to fetch firecrawl: %s", err)
		}

		var result mapResponse
		if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&result); err != nil {
			return fmt.Errorf("failed to decode firecrawl result: %s", err)
		}
		if !result.Success {
			if result.Error != "" {
				return fmt.Errorf("firecrawl error: %s", result.Error)
			}
			return fmt.Errorf("firecrawl returned success=false")
		}

		for _, raw := range result.Links {
			found := parseLink(raw)
			if found == "" {
				continue
			}
			if providers.MatchesDomain(found, domain, c.config.IncludeSubdomains) {
				select {
				case <-ctx.Done():
					return nil
				case results <- found:
				}
			}
		}

		return nil
	}
}

func parseLink(raw jsoniter.RawMessage) string {
	var asString string
	if err := jsoniter.Unmarshal(raw, &asString); err == nil {
		return asString
	}

	var obj linkObject
	if err := jsoniter.Unmarshal(raw, &obj); err == nil {
		return obj.URL
	}

	return ""
}

func waitForRateLimit() {
	rateMu.Lock()
	defer rateMu.Unlock()

	const interval = 6 * time.Second
	if since := time.Since(lastCall); since < interval {
		time.Sleep(interval - since)
	}
	lastCall = time.Now()
}
