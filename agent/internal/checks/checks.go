// Package checks holds the individual host checks. Each returns a slice of
// report.Finding (empty = nothing wrong) or an error (check could not run -
// central then leaves that kind's prior findings untouched).
package checks

import "os"

// Hostname is the reported host name. PICKET_HOSTNAME overrides it (tests,
// containers).
func Hostname() string {
	if h := os.Getenv("PICKET_HOSTNAME"); h != "" {
		return h
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}
