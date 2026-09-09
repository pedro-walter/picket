// Package httpdl is a tiny shared HTTP download helper used by selfupdate and
// tools: stream to a writer while hashing, or fetch a small body into memory.
package httpdl

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
)

const maxBytes = 300 << 20 // 300 MiB ceiling for any single download

// ToWriter streams url into w and returns the SHA-256 of the bytes written.
func ToWriter(ctx context.Context, hc *http.Client, url string, w io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxBytes)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Bytes fetches a small body (signatures, checksum files) into memory.
func Bytes(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
