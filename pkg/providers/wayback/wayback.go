package wayback

import (
	"context"
	"errors"
	"fmt"
	"net"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

const (
	Name = "wayback"
)

// verify interface compliance
var _ providers.Provider = (*Client)(nil)

// Client is the structure that holds the WaybackFilters and the Client's configuration
type Client struct {
	filters providers.Filters
	config  *providers.Config
}

func New(config *providers.Config, filters providers.Filters) *Client {
	return &Client{filters, config}
}

func (c *Client) Name() string {
	return Name
}

// waybackResult holds the response from the wayback API
type waybackResult [][]string

// Fetch fetches all urls for a given domain and sends them to a channel.
// It returns an error should one occur.
func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	consecutiveFailures := uint(0)
	maxFailures := c.failureBudget()

	for page := uint(0); ; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)
			apiURL := c.formatURL(domain, page)
			// make HTTP request
			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout)
			if err != nil {
				if errors.Is(err, httpclient.ErrBadRequest) {
					return nil
				}
				if shouldSkipWaybackPage(err) {
					consecutiveFailures++
					logrus.WithFields(logrus.Fields{
						"provider": Name,
						"page":     page,
					}).Warnf("skipping wayback page after error: %v", err)
					if consecutiveFailures >= maxFailures {
						logrus.WithFields(logrus.Fields{
							"provider": Name,
							"page":     page,
						}).Warn("stopping wayback fetch due to repeated errors")
						return nil
					}
					continue
				}
				return fmt.Errorf("failed to fetch wayback results page %d: %s", page, err)
			}
			consecutiveFailures = 0
			var result waybackResult
			if err = jsoniter.Unmarshal(resp, &result); err != nil {
				return fmt.Errorf("failed to decode wayback results for page %d: %s", page, err)
			}

			// check if there's results, wayback's pagination response
			// is not always correct when using a filter
			if len(result) == 0 {
				break
			}

			// output results
			// Slicing as [1:] to skip first result by default
			for _, entry := range result[1:] {
				results <- entry[0]
			}
		}
	}

	return nil
}

// formatUrl returns a formatted URL for the Wayback API
func (c *Client) formatURL(domain string, page uint) string {
	if c.config.IncludeSubdomains {
		domain = "*." + domain
	}
	filterParams := c.filters.GetParameters(true)
	return fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original&pageSize=100&page=%d",
		domain, page,
	) + filterParams
}

func (c *Client) failureBudget() uint {
	if c.config.MaxRetries > 0 {
		return c.config.MaxRetries
	}

	return 3
}

func shouldSkipWaybackPage(err error) bool {
	if errors.Is(err, fasthttp.ErrTimeout) {
		return true
	}

	if errors.Is(err, httpclient.ErrNon200Response) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}
