package intelx

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
	Name = "intelx"

	maxPolls  = 30
	pageLimit = 1000
)

// pollInterval is a variable so tests can shorten it.
var pollInterval = 2 * time.Second

// searchURL and resultURL are variables so tests can point them at a local server.
var (
	searchURL = "https://2.intelx.io/phonebook/search"
	resultURL = "https://2.intelx.io/phonebook/search/result"

	rateMu   sync.Mutex
	lastCall time.Time
)

var _ providers.Provider = (*Client)(nil)

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
	ID     string `json:"id"`
	Status int    `json:"status"`
}

type resultResponse struct {
	Selectors []struct {
		Selector string `json:"selector"`
	} `json:"selectors"`
	Status int `json:"status"`
}

// Status codes returned by /phonebook/search/result.
const (
	statusResults  = 0
	statusNoMore   = 1
	statusNotFound = 2
	statusPending  = 3
)

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if len(c.config.IntelX.APIKeys) == 0 {
		logrus.WithField("provider", Name).Debug("no intelx apikey provided, skipping")
		return nil
	}

	select {
	case <-ctx.Done():
		return nil
	default:
	}

	waitForRateLimit()
	logrus.WithFields(logrus.Fields{"provider": Name}).Infof("fetching %s", domain)

	searchID, err := c.startSearch(domain)
	if err != nil {
		return fmt.Errorf("failed to start intelx search: %s", err)
	}

	for poll := 0; poll < maxPolls; poll++ {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}

		done, err := c.fetchResults(ctx, domain, searchID, results)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}

	logrus.WithField("provider", Name).Warnf("%s - search %s did not finish after %d polls", domain, searchID, maxPolls)
	return nil
}

func (c *Client) startSearch(domain string) (string, error) {
	body, err := jsoniter.Marshal(map[string]any{
		"term":       domain,
		"maxresults": 100000,
		"media":      0,
		"target":     3, // URLs
		"timeout":    20,
	})
	if err != nil {
		return "", err
	}

	header := httpclient.Header{Key: "x-key", Value: providers.PickKey(Name, c.config.IntelX.APIKeys)}
	resp, err := httpclient.MakeJSONRequest(c.config.Client, searchURL, body, c.config.MaxRetries, c.timeout(), header)
	if err != nil {
		return "", err
	}

	var s searchResponse
	if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&s); err != nil {
		return "", fmt.Errorf("failed to decode search response: %s", err)
	}
	if s.ID == "" {
		return "", fmt.Errorf("search response had no id")
	}
	return s.ID, nil
}

// fetchResults returns done=true when the search has no more results.
func (c *Client) fetchResults(ctx context.Context, domain, searchID string, results chan string) (bool, error) {
	url := fmt.Sprintf("%s?id=%s&limit=%d&offset=-1", resultURL, searchID, pageLimit)
	header := httpclient.Header{Key: "x-key", Value: providers.PickKey(Name, c.config.IntelX.APIKeys)}
	resp, err := httpclient.MakeRequest(c.config.Client, url, c.config.MaxRetries, c.timeout(), header)
	if err != nil {
		return true, fmt.Errorf("failed to fetch intelx results: %s", err)
	}

	var r resultResponse
	if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&r); err != nil {
		return true, fmt.Errorf("failed to decode intelx results: %s", err)
	}

	switch r.Status {
	case statusPending:
		return false, nil
	case statusNotFound:
		return true, fmt.Errorf("intelx search %s not found", searchID)
	case statusNoMore:
		return true, nil
	}

	for _, s := range r.Selectors {
		if !providers.MatchesDomain(s.Selector, domain, c.config.IncludeSubdomains) {
			continue
		}
		select {
		case <-ctx.Done():
			return true, nil
		case results <- s.Selector:
		}
	}

	// statusResults: the page had data, so keep reading until the server says it is done.
	return false, nil
}

func (c *Client) timeout() uint {
	if c.config.Timeout < 30 {
		return 30
	}
	return c.config.Timeout
}

func waitForRateLimit() {
	rateMu.Lock()
	defer rateMu.Unlock()

	const interval = 2 * time.Second
	if since := time.Since(lastCall); since < interval {
		time.Sleep(interval - since)
	}
	lastCall = time.Now()
}
