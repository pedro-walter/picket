// Package toolexec runs the external single-binary tools the agent drives
// (crane, trivy), resolving them from the managed bin dir first, then $PATH.
package toolexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Runner runs an external tool and returns its stdout. Implementations are
// swapped for fakes in tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OS runs real binaries. BinDir (e.g. /var/lib/picket/bin) is tried before
// $PATH so a tools.auto_manage download wins over a distro package.
type OS struct {
	BinDir  string
	Timeout time.Duration
	Env     []string // extra env appended to os.Environ() (e.g. DOCKER_CONFIG)
}

func (o OS) resolve(name string) (string, error) {
	if o.BinDir != "" {
		p := filepath.Join(o.BinDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

func (o OS) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := o.resolve(name)
	if err != nil {
		return nil, fmt.Errorf("%s not found (install it or enable tools.auto_manage): %w", name, err)
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), o.Env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}
