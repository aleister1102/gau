package virustotal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

const (
	Name = "virustotal"
)

var _ providers.Provider = (*Client)(nil)

type Client struct {
	config     *providers.Config
	httpClient *fasthttp.Client
}

func New(c *providers.Config) *Client {
	// The shared client can disable TLS verification. Verify the peer before
	// sending a key in the query string, while retaining the configured dialer.
	client := &fasthttp.Client{TLSConfig: &tls.Config{}}
	if c.Client != nil {
		client.Dial = c.Client.Dial
		if c.Client.TLSConfig != nil {
			client.TLSConfig = c.Client.TLSConfig.Clone()
			client.TLSConfig.InsecureSkipVerify = false
		}
	}
	return &Client{config: c, httpClient: client}
}

func (c *Client) Name() string {
	return Name
}

type domainReport struct {
	ResponseCode *int `json:"response_code"`
	DetectedURLs []struct {
		URL string `json:"url"`
	} `json:"detected_urls"`
	// Only the first element is the URL; JSON decoding discards the remaining metadata.
	UndetectedURLs [][1]string `json:"undetected_urls"`
}

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	if len(c.config.VirusTotal.APIKeys) == 0 {
		logrus.WithField("provider", Name).Debug("no virustotal apikey provided, skipping")
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	logrus.WithField("provider", Name).Infof("fetching %s", domain)
	urls, err := c.fetchReportURLs(domain)
	if err != nil {
		return err
	}

	for _, rawURL := range urls {
		scheme, _, _ := strings.Cut(rawURL, ":")
		if !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
			continue
		}
		if !providers.MatchesDomain(rawURL, domain, c.config.IncludeSubdomains) {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case results <- rawURL:
		}
	}
	return nil
}

func (c *Client) fetchReportURLs(domain string) ([]string, error) {
	query := url.Values{
		"apikey": {providers.PickKey(Name, c.config.VirusTotal.APIKeys)},
		"domain": {domain},
	}
	apiURL := "https://www.virustotal.com/vtapi/v2/domain/report?" + query.Encode()
	body, err := httpclient.MakeRequest(c.httpClient, apiURL, c.config.MaxRetries, c.config.Timeout)
	switch err {
	case nil:
	case httpclient.ErrBadRequest, httpclient.ErrNon200Response, httpclient.ErrNilResponse, fasthttp.ErrTimeout:
		return nil, fmt.Errorf("failed to request virustotal domain report: %w", err)
	default:
		// A transport error can contain the request URL, including the API key.
		return nil, errors.New("failed to request virustotal domain report")
	}

	var report domainReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, errors.New("failed to decode virustotal domain report")
	}
	if report.ResponseCode == nil {
		return nil, errors.New("missing virustotal domain report response code")
	}
	switch *report.ResponseCode {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, errors.New("unexpected virustotal domain report response code")
	}

	urls := make([]string, 0, len(report.DetectedURLs)+len(report.UndetectedURLs))
	for _, detected := range report.DetectedURLs {
		urls = append(urls, detected.URL)
	}
	for _, undetected := range report.UndetectedURLs {
		urls = append(urls, undetected[0])
	}
	return urls, nil
}
