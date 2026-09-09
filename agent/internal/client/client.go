// Package client is the authenticated transport to the picket central service.
package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pedrohardware/picket/agent/internal/report"
)

// Client POSTs reports to central with per-agent bearer auth plus an HMAC
// over "timestamp + \".\" + rawBody" (replay protection, body integrity).
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
	now     func() time.Time
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second},
		now:     time.Now,
	}
}

// sign computes the lowercase-hex HMAC-SHA256 the server recomputes in
// auth.ts: hmac(token, timestamp + "." + body).
func sign(token, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SendReport POSTs one consolidated report and returns the self-update hint.
func (c *Client) SendReport(ctx context.Context, p *report.Payload) (*report.Response, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(c.now().Unix(), 10)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/report", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Picket-Timestamp", ts)
	req.Header.Set("X-Picket-Signature", sign(c.token, ts, body))

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("central returned %d: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var out report.Response
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decoding central response: %w", err)
	}
	return &out, nil
}
