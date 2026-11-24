package virustotal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lc/gau/v2/pkg/providers"
	"github.com/valyala/fasthttp"
)

func TestFetchDomainReport(t *testing.T) {
	const (
		domain     = "example.com"
		key        = "local test+key&value=#"
		serverText = "untrusted response text"
		report     = `{
			"response_code": 1,
			"detected_urls": [
				{"url": "https://example.com/detected?q=one"},
				{"url": "http://api.example.com/detected"},
				{"url": "https://notexample.com/other"},
				{"url": "ftp://example.com/not-http"}
			],
			"undetected_urls": [
				["https://example.com/undetected", "some-hash", 0, 80, "2026-01-01"],
				["https://www.example.com/undetected", "other-hash", 0, 80, "2026-01-01"],
				["https://example.com.other.test/other", "some-hash", 0, 80, "2026-01-01"],
				["//example.com/no-scheme", "some-hash", 0, 80, "2026-01-01"]
			]
		}`
	)

	tests := []struct {
		name              string
		includeSubdomains bool
		status            int
		body              string
		wantURLs          []string
		wantErr           bool
	}{
		{
			name: "exact domain only",
			body: report,
			wantURLs: []string{
				"https://example.com/detected?q=one",
				"https://example.com/undetected",
			},
		},
		{
			name:              "includes subdomains",
			includeSubdomains: true,
			body:              report,
			wantURLs: []string{
				"http://api.example.com/detected",
				"https://example.com/detected?q=one",
				"https://example.com/undetected",
				"https://www.example.com/undetected",
			},
		},
		{
			name: "no report",
			body: `{"response_code":0}`,
		},
		{
			name:    "does not follow redirect",
			status:  http.StatusFound,
			body:    serverText,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.Host != "www.virustotal.com" || r.URL.Path != "/vtapi/v2/domain/report" {
					t.Errorf("unexpected request method, host, or path: %s %s%s", r.Method, r.Host, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				query := r.URL.Query()
				if query.Get("domain") != domain || query.Get("apikey") != key {
					t.Error("request did not send the expected domain and key as query parameters")
					http.Error(w, "bad report query", http.StatusBadRequest)
					return
				}
				if tt.status == http.StatusFound {
					w.Header().Set("Location", "/redirect-target?"+r.URL.RawQuery)
					w.WriteHeader(tt.status)
				}
				io.WriteString(w, tt.body)
			}))
			defer server.Close()

			addr := server.Listener.Addr().String()
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			cfg := &providers.Config{
				Client: &fasthttp.Client{
					Dial: func(string) (net.Conn, error) {
						return net.Dial("tcp", addr)
					},
					TLSConfig: &tls.Config{RootCAs: roots, ServerName: host},
				},
				Timeout:           5,
				IncludeSubdomains: tt.includeSubdomains,
				VirusTotal:        providers.VirusTotalConfig{APIKeys: []string{key}},
			}
			results := make(chan string, 16)
			err = New(cfg).Fetch(context.Background(), domain, results)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Fetch returned error = %v, want error = %t", err, tt.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), key) || strings.Contains(err.Error(), url.QueryEscape(key)) || strings.Contains(err.Error(), serverText)) {
				t.Error("Fetch exposed the key or the response text in an error")
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("got %d HTTP requests, want 1", got)
			}

			close(results)
			var got []string
			for result := range results {
				got = append(got, result)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantURLs) {
				t.Errorf("got URLs %v, want %v", got, tt.wantURLs)
			}
		})
	}
}
