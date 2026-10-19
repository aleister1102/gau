package arquivopt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "arquivopt"
)

var _ providers.Provider = (*Client)(nil)

type Client struct {
	config  *providers.Config
	filters providers.Filters
}

func New(c *providers.Config, filters providers.Filters) *Client {
	return &Client{config: c, filters: filters}
}

func (c *Client) Name() string {
	return Name
}

type cdxEntry struct {
	URL string `json:"url"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	select {
	case <-ctx.Done():
		return nil
	default:
		logrus.WithFields(logrus.Fields{"provider": Name}).Infof("fetching %s", domain)
		apiURL := c.formatURL(domain)
		resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout)
		if err != nil {
			return fmt.Errorf("failed to fetch arquivopt results: %s", err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(resp))
		const maxLineLength = 1024 * 1024
		buf := make([]byte, maxLineLength)
		scanner.Buffer(buf, maxLineLength)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return nil
			default:
				line := scanner.Bytes()
				if len(line) == 0 {
					continue
				}
				var entry cdxEntry
				if err := jsoniter.Unmarshal(line, &entry); err != nil {
					continue
				}
				if entry.URL != "" {
					results <- entry.URL
				}
			}
		}

		return scanner.Err()
	}
}

func (c *Client) formatURL(domain string) string {
	encodedDomain := url.QueryEscape(domain)
	filterParams := c.filters.GetParameters(true)

	if c.config.IncludeSubdomains {
		return fmt.Sprintf("https://arquivo.pt/wayback/cdx?url=%s&matchType=domain&output=json%s", encodedDomain, filterParams)
	}

	return fmt.Sprintf("https://arquivo.pt/wayback/cdx?url=%s/*&output=json%s", encodedDomain, filterParams)
}
