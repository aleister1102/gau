package providers

import (
	"strings"
	"sync"
	"sync/atomic"
)

var keyCounters sync.Map // provider name -> *atomic.Uint64

// PickKey returns the next key for the named provider in round-robin order.
// It returns "" when keys is empty.
func PickKey(name string, keys []string) string {
	switch len(keys) {
	case 0:
		return ""
	case 1:
		return keys[0]
	}
	v, _ := keyCounters.LoadOrStore(name, new(atomic.Uint64))
	idx := v.(*atomic.Uint64).Add(1) - 1
	return keys[idx%uint64(len(keys))]
}

// SplitKeys splits comma-separated values, trims spaces, and drops empty entries and duplicates.
func SplitKeys(values ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
