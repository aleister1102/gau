package virustotal

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "virustotal"
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

type vtURLResponse struct {
	Data []struct {
		Attributes struct {
			URL string `json:"url"`
		} `json:"attributes"`
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type vtSubdomainResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if c.config.VirusTotal.APIKey == "" {
		logrus.WithField("provider", Name).Debug("no virustotal apikey provided, skipping")
		return nil
	}

	header := httpclient.Header{
		Key:   "x-apikey",
		Value: c.config.VirusTotal.APIKey,
	}

	cursor := ""
	for page := uint(0); ; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)
			apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/urls?limit=40", domain)
			if cursor != "" {
				apiURL += "&cursor=" + cursor
			}

			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout, header)
			if err != nil {
				// The /urls endpoint is restricted on many community keys, and
				// httpclient collapses non-200 status codes into one error. Fall
				// back to /subdomains so the provider still returns data.
				logrus.WithField("provider", Name).Infof("virustotal urls endpoint unavailable (%v), querying subdomains", err)
				return c.fetchSubdomains(ctx, domain, header, results)
			}

			var result vtURLResponse
			if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&result); err != nil {
				return fmt.Errorf("failed to decode virustotal result: %s", err)
			}

			if result.Error != nil {
				if result.Error.Code == "ForbiddenError" {
					return c.fetchSubdomains(ctx, domain, header, results)
				}
				return fmt.Errorf("virustotal error: %s", result.Error.Message)
			}

			for _, item := range result.Data {
				if item.Attributes.URL != "" {
					results <- item.Attributes.URL
				}
			}

			if result.Links.Next == "" {
				return nil
			}

			cursor = parseCursor(result.Links.Next)
			if cursor == "" {
				return nil
			}
		}
	}
}

func (c *Client) fetchSubdomains(ctx context.Context, domain string, header httpclient.Header, results chan string) error {
	cursor := ""
	for page := uint(0); ; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
			if cursor != "" {
				apiURL += "&cursor=" + cursor
			}

			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout, header)
			if err != nil {
				return nil
			}

			var result vtSubdomainResponse
			if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&result); err != nil {
				return nil
			}

			for _, item := range result.Data {
				if item.ID != "" {
					results <- fmt.Sprintf("https://%s/", item.ID)
				}
			}

			if result.Links.Next == "" {
				return nil
			}

			cursor = parseCursor(result.Links.Next)
			if cursor == "" {
				return nil
			}
		}
	}
}

func parseCursor(nextURL string) string {
	parts := strings.Split(nextURL, "cursor=")
	if len(parts) > 1 {
		return strings.Split(parts[1], "&")[0]
	}
	return ""
}
