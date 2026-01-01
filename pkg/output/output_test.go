package output

import (
	"bytes"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
)

func TestWriteURLs(t *testing.T) {
	tests := []struct {
		name             string
		results          []string
		blacklist        []string
		removeParameters bool
		expected         string
	}{
		{
			name:             "No filtering",
			results:          []string{"http://example.com/a?q=1", "http://example.com/a?q=2"},
			blacklist:        []string{},
			removeParameters: false,
			expected:         "http://example.com/a?q=1\nhttp://example.com/a?q=2\n",
		},
		{
			name:             "Remove parameters filters duplicates",
			results:          []string{"http://example.com/a?q=1", "http://example.com/a?q=2", "http://example.com/b"},
			blacklist:        []string{},
			removeParameters: true,
			expected:         "http://example.com/a?q=1\nhttp://example.com/b\n",
		},
		{
			name:             "Blacklist filtering (dotless extension)",
			results:          []string{"http://example.com/a.png", "http://example.com/b.html"},
			blacklist:        []string{"png"},
			removeParameters: false,
			expected:         "http://example.com/b.html\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultsChan := make(chan string, len(tt.results))
			for _, r := range tt.results {
				resultsChan <- r
			}
			close(resultsChan)

			blacklistMap := mapset.NewThreadUnsafeSet(tt.blacklist...)
			var buf bytes.Buffer
			err := WriteURLs(&buf, resultsChan, blacklistMap, tt.removeParameters)
			if err != nil {
				t.Fatalf("WriteURLs unexpected error: %v", err)
			}

			if buf.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, buf.String())
			}
		})
	}
}
