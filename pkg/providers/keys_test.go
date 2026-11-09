package providers

import (
	"reflect"
	"testing"
)

func TestPickKeyRotatesRoundRobin(t *testing.T) {
	keys := []string{"a", "b", "c"}
	var got []string
	for i := 0; i < 6; i++ {
		got = append(got, PickKey("rotate-test", keys))
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PickKey order = %v, want %v", got, want)
	}
}

func TestPickKeyEmpty(t *testing.T) {
	if k := PickKey("empty-test", nil); k != "" {
		t.Fatalf("PickKey(nil) = %q, want empty", k)
	}
}

func TestSplitKeys(t *testing.T) {
	got := SplitKeys(" a, b ,,a", "c", "")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitKeys = %v, want %v", got, want)
	}
}
