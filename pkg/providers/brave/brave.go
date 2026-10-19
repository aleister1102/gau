package brave

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "brave"
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

type searchResponse struct {
	Web struct {
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	} `json:"web"`
	Error *struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"error"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if c.config.Brave.APIKey == "" {
		logrus.WithField("provider", Name).Debug("no brave apikey provided, skipping")
		return nil
	}

	header := httpclient.Header{
		Key:   "X-Subscription-Token",
		Value: c.config.Brave.APIKey,
	}

	for page := 0; page < 3; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			waitForRateLimit()
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)

			query := url.Values{}
			query.Set("q", "site:"+domain)
			query.Set("count", "20")
			query.Set("offset", fmt.Sprintf("%d", page))
			apiURL := "https://api.search.brave.com/res/v1/web/search?" + query.Encode()

			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout, header)
			if err != nil {
				if page == 0 {
					return fmt.Errorf("failed to fetch brave: %s", err)
				}
				return nil
			}

			var result searchResponse
			if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode brave result: %s", err)
			}
			if result.Error != nil {
				if result.Error.Status == 429 || result.Error.Code == "RATE_LIMITED" {
					logrus.WithField("provider", Name).Warn("brave rate limit reached, stopping")
					return nil
				}
				return fmt.Errorf("brave error: %s", result.Error.Detail)
			}

			for _, item := range result.Web.Results {
				if providers.MatchesDomain(item.URL, domain, c.config.IncludeSubdomains) {
					select {
					case <-ctx.Done():
						return nil
					case results <- item.URL:
					}
				}
			}

			if len(result.Web.Results) < 20 {
				return nil
			}
		}
	}

	return nil
}

func waitForRateLimit() {
	rateMu.Lock()
	defer rateMu.Unlock()

	const interval = 1500 * time.Millisecond
	if since := time.Since(lastCall); since < interval {
		time.Sleep(interval - since)
	}
	lastCall = time.Now()
}
