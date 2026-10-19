package ghostarchive

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "ghostarchive"
)

var _ providers.Provider = (*Client)(nil)

var linkRegex = regexp.MustCompile(`href="/archive/[a-zA-Z0-9_-]+">(https?://[^<]+)</a>`)

type Client struct {
	config *providers.Config
}

func New(c *providers.Config) *Client {
	return &Client{config: c}
}

func (c *Client) Name() string {
	return Name
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	select {
	case <-ctx.Done():
		return nil
	default:
		logrus.WithFields(logrus.Fields{"provider": Name}).Infof("fetching %s", domain)
		searchURL := fmt.Sprintf("https://ghostarchive.org/search?term=%s", url.QueryEscape(domain))
		resp, err := httpclient.MakeRequest(c.config.Client, searchURL, c.config.MaxRetries, c.config.Timeout)
		if err != nil {
			return fmt.Errorf("failed to fetch ghostarchive results: %s", err)
		}

		matches := linkRegex.FindAllSubmatch(resp, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			foundURL := strings.TrimSpace(string(m[1]))
			parsed, err := url.Parse(foundURL)
			if err != nil {
				continue
			}

			hostname := strings.ToLower(parsed.Hostname())
			targetDomain := strings.ToLower(domain)

			if hostname == targetDomain || (c.config.IncludeSubdomains && strings.HasSuffix(hostname, "."+targetDomain)) {
				select {
				case <-ctx.Done():
					return nil
				case results <- foundURL:
				}
			}
		}

		return nil
	}
}
