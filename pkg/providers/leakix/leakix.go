package leakix

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "leakix"
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

type leakixResult struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	HTTP     struct {
		Root string `json:"root"`
		URL  string `json:"url"`
	} `json:"http"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if c.config.LeakIX.APIKey == "" {
		logrus.WithField("provider", Name).Debug("no leakix apikey provided, skipping")
		return nil
	}

	header := []httpclient.Header{{
		Key:   "api-key",
		Value: c.config.LeakIX.APIKey,
	}, {
		Key:   "Accept",
		Value: "application/json",
	}}

	targetDomain := strings.ToLower(domain)
	seen := make(map[string]struct{})

	for page := uint(0); ; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)
			apiURL := fmt.Sprintf(
				"https://leakix.net/search?scope=service&q=%s&page=%d",
				url.QueryEscape("host:"+domain), page,
			)

			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout, header...)
			if err != nil {
				if page == 0 {
					return fmt.Errorf("failed to fetch leakix: %s", err)
				}
				return nil
			}

			if len(resp) == 0 || string(resp) == "null" {
				return nil
			}

			var items []leakixResult
			if err := jsoniter.NewDecoder(bytes.NewReader(resp)).Decode(&items); err != nil {
				return fmt.Errorf("failed to decode leakix result: %s", err)
			}

			if len(items) == 0 {
				return nil
			}

			for _, item := range items {
				host := strings.ToLower(item.Host)
				if host == "" {
					continue
				}

				if host != targetDomain && !(c.config.IncludeSubdomains && strings.HasSuffix(host, "."+targetDomain)) {
					continue
				}

				proto := item.Protocol
				if proto == "" {
					proto = "https"
				}

				authority := host
				if item.Port != "" &&
					!((proto == "http" && item.Port == "80") || (proto == "https" && item.Port == "443")) {
					authority = fmt.Sprintf("%s:%s", host, item.Port)
				}

				paths := []string{"/"}
				for _, p := range []string{item.HTTP.Root, item.HTTP.URL} {
					if p != "" && p != "/" {
						paths = append(paths, p)
					}
				}

				for _, p := range paths {
					found := fmt.Sprintf("%s://%s%s", proto, authority, p)
					if _, ok := seen[found]; ok {
						continue
					}
					seen[found] = struct{}{}

					select {
					case <-ctx.Done():
						return nil
					case results <- found:
					}
				}
			}
		}
	}
}
