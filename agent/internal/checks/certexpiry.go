package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pedro-walter/picket/agent/internal/report"
)

// CertExpiry reports (kind "cert-expiry") a domain whose live TLS leaf cert
// is within ThresholdDays of expiry, or whose handshake fails. Ports
// check-cert-expiry.sh using a real TLS dial (Go crypto/tls, no openssl
// shell-out). Meant for the daily section.
type CertExpiry struct {
	Domains       []string
	ThresholdDays int           // default 14
	DialTimeout   time.Duration // default 10s
	// NotAfter resolves a domain's leaf-cert expiry; nil => real TLS dial.
	NotAfter func(ctx context.Context, domain string, timeout time.Duration) (time.Time, error)
	Now      func() time.Time
}

func (c CertExpiry) Scan(ctx context.Context) ([]report.Finding, error) {
	if len(c.Domains) == 0 {
		return nil, nil
	}
	td := c.ThresholdDays
	if td <= 0 {
		td = 14
	}
	to := c.DialTimeout
	if to <= 0 {
		to = 10 * time.Second
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	resolve := peerNotAfter
	if c.NotAfter != nil {
		resolve = c.NotAfter
	}

	var findings []report.Finding
	for _, raw := range c.Domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		na, err := resolve(ctx, d, to)
		if err != nil {
			findings = append(findings, report.Finding{
				Kind:       "cert-expiry",
				Subject:    d,
				Identifier: "handshake",
				Severity:   "high",
				Title:      d + ": TLS handshake / certificate read failed",
				Detail:     err.Error(),
			})
			continue
		}
		daysLeft := int(na.Sub(now()) / (24 * time.Hour))
		if daysLeft >= td {
			continue
		}
		sev := "medium"
		switch {
		case daysLeft < 3:
			sev = "critical"
		case daysLeft < 7:
			sev = "high"
		}
		title := fmt.Sprintf("%s: TLS certificate expires in %dd", d, daysLeft)
		if daysLeft < 0 {
			title = fmt.Sprintf("%s: TLS certificate expired %dd ago", d, -daysLeft)
		}
		findings = append(findings, report.Finding{
			Kind:       "cert-expiry",
			Subject:    d,
			Identifier: "expiry",
			Severity:   sev,
			Title:      title,
			Detail:     "notAfter " + na.UTC().Format(time.RFC3339) + fmt.Sprintf(" (threshold %dd)", td),
		})
	}
	return findings, nil
}

func peerNotAfter(ctx context.Context, domain string, timeout time.Duration) (time.Time, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // we only need NotAfter, mirroring `openssl x509 -enddate`
	})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, errors.New("no peer certificate presented")
	}
	return certs[0].NotAfter, nil
}
