package intelx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/lc/gau/v2/pkg/providers"
	"github.com/valyala/fasthttp"
)

func TestFetchFiltersAndFollowsStatuses(t *testing.T) {
	var mu sync.Mutex
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-key") != "test-key" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/search":
			fmt.Fprint(w, `{"id":"abc","status":0}`)
		case "/result":
			mu.Lock()
			polls++
			n := polls
			mu.Unlock()
			switch n {
			case 1: // still working, no data yet
				fmt.Fprint(w, `{"selectors":[],"status":3}`)
			case 2: // data for this domain, the other domain is dropped
				fmt.Fprint(w, `{"selectors":[{"selector":"https://example.com/a"},{"selector":"https://other.org/x"},{"selector":"https://api.example.com/b"}],"status":0}`)
			default: // done
				fmt.Fprint(w, `{"selectors":[],"status":1}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origSearch, origResult := searchURL, resultURL
	defer func() {
		searchURL, resultURL = origSearch, origResult
	}()
	searchURL = srv.URL + "/search"
	resultURL = srv.URL + "/result"

	// Keep the test fast: the real poll interval is 2 seconds.
	prev := pollInterval
	pollInterval = 0
	defer func() { pollInterval = prev }()

	cfg := &providers.Config{
		Client:     &fasthttp.Client{},
		Timeout:    5,
		MaxRetries: 0,
		IntelX:     providers.IntelXConfig{APIKeys: []string{"test-key"}},
	}

	results := make(chan string, 100)
	if err := New(cfg).Fetch(context.Background(), "example.com", results); err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	close(results)

	var got []string
	for u := range results {
		got = append(got, u)
	}
	sort.Strings(got)

	want := []string{"https://example.com/a"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFetchSkipsWithoutKey(t *testing.T) {
	cfg := &providers.Config{Client: &fasthttp.Client{}, Timeout: 5}
	results := make(chan string, 1)
	if err := New(cfg).Fetch(context.Background(), "example.com", results); err != nil {
		t.Fatalf("expected no error without key, got %v", err)
	}
	close(results)
	if _, ok := <-results; ok {
		t.Fatal("expected no results without key")
	}
}
