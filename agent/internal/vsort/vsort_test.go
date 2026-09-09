package vsort

import (
	"sort"
	"testing"
)

func TestLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool // a < b
	}{
		{"16.9-alpine", "16.14-alpine", true}, // numeric run compares as 9 < 14
		{"16.14-alpine", "16.9-alpine", false},
		{"v3.7", "v3.7.1", true},    // shorter prefix sorts first
		{"v3.7.1", "v3.11.0", true}, // 7 < 11 numerically
		{"1.2.3", "1.2.3", false},
		{"0.56.0-alpine", "0.57.0-alpine", true},
		{"v2.1.9", "v2.1.20", true}, // 9 < 20 numerically, not lexically
		{"16-alpine", "16.1-alpine", true},
	}
	for _, c := range cases {
		if got := Less(c.a, c.b); got != c.want {
			t.Errorf("Less(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSortPicksNewest(t *testing.T) {
	tags := []string{"16.1-alpine", "16.14-alpine", "16.9-alpine", "16-alpine", "16.2-alpine"}
	sort.Slice(tags, func(i, j int) bool { return Less(tags[i], tags[j]) })
	if got := tags[len(tags)-1]; got != "16.14-alpine" {
		t.Errorf("newest = %q, want 16.14-alpine", got)
	}
}
