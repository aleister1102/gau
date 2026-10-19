package serpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "serpapi"
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
	OrganicResults []struct {
		Link string `json:"link"`
	} `json:"organic_results"`
	Error string `json:"error"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if c.config.SerpAPI.APIKey == "" {
		logrus.WithField("provider", Name).Debug("no serpapi apikey provided, skipping")
		return nil
	}

	start := 0
	for page := 0; page < 3; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			waitForRateLimit()
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)

			query := url.Values{}
			query.Set("engine", "google")
			query.Set("q", "site:"+domain)
			query.Set("num", "100")
			query.Set("start", strconv.Itoa(start))
			query.Set("api_key", c.config.SerpAPI.APIKey)
			apiURL := "https://serpapi.com/search.json?" + query.Encode()

			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout)
			if err != nil {
				if page == 0 {
					return fmt.Errorf("failed to fetch serpapi: %s", err)
				}
				return nil
			}

			var result searchResponse
			if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode serpapi result: %s", err)
			}
			if result.Error != "" {
				if strings.Contains(result.Error, "hasn't returned any results") {
					return nil
				}
				return fmt.Errorf("serpapi error: %s", result.Error)
			}
			if len(result.OrganicResults) == 0 {
				return nil
			}

			for _, item := range result.OrganicResults {
				if providers.MatchesDomain(item.Link, domain, c.config.IncludeSubdomains) {
					select {
					case <-ctx.Done():
						return nil
					case results <- item.Link:
					}
				}
			}

			start += len(result.OrganicResults)
			if len(result.OrganicResults) < 10 {
				return nil
			}
		}
	}

	return nil
}

func waitForRateLimit() {
	rateMu.Lock()
	defer rateMu.Unlock()

	const interval = 1100 * time.Millisecond
	if since := time.Since(lastCall); since < interval {
		time.Sleep(interval - since)
	}
	lastCall = time.Now()
}
