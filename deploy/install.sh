#!/bin/sh
# picket-agent bootstrap / disaster-recovery installer.
#
#   curl -fsSL https://raw.githubusercontent.com/pedro-walter/picket/main/deploy/install.sh | sudo sh -s -- \
#     --central https://picket.souspike.com.br --name prod-server --token <TOKEN> \
#     --version v0.2.0
#
# Re-runnable: also the manual upgrade path (--upgrade just re-drops the unit
# + re-installs the pinned binary). Self-update handles routine upgrades once
# running; this is the floor / recovery tool.
set -eu

CENTRAL="" NAME="" TOKEN="" VERSION="" UPGRADE=0
REPO="${PICKET_REPO:-pedro-walter/picket}"
RELEASE_BASE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --central) CENTRAL="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --release-base) RELEASE_BASE="$2"; shift 2 ;;
    --upgrade) UPGRADE=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [ "$UPGRADE" -eq 0 ]; then
  [ -n "$CENTRAL" ] && [ -n "$NAME" ] && [ -n "$TOKEN" ] || {
    echo "usage: install.sh --central URL --name AGENT_NAME --token TOKEN --version vX.Y.Z" >&2
    exit 2
  }
fi
[ -n "$VERSION" ] || { echo "--version vX.Y.Z is required" >&2; exit 2; }
V="${VERSION#v}"
[ -n "$RELEASE_BASE" ] || RELEASE_BASE="https://github.com/${REPO}/releases/download/v${V}"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 2 ;;
esac
BIN="picket-agent_${V}_linux_${GOARCH}"

# --- user / dirs --------------------------------------------------------
id -u picket >/dev/null 2>&1 || useradd --system --home /var/lib/picket --shell /usr/sbin/nologin picket
getent group docker >/dev/null 2>&1 && usermod -aG docker picket || true
install -d -o root  -g picket -m 0750 /etc/picket
install -d -o picket -g picket -m 0755 /var/lib/picket /var/lib/picket/bin

# --- config + token (only on first install) ---------------------------
if [ "$UPGRADE" -eq 0 ] && [ ! -f /etc/picket/agent.yaml ]; then
  cat > /etc/picket/agent.yaml <<YAML
central_url: $CENTRAL
agent_name: $NAME
token_file: /etc/picket/token
report_interval: 15m
image_scan_interval: 12h
daily_interval: 24h
self_update: true
update_window: "02:00-04:00"
compose_files: []
domains: []
paths: {disk: /}
thresholds: {cpu_pct: 90, mem_pct: 90, disk_pct: 85, mongo_data_gb: 20, registry_data_gb: 15}
tools: {auto_manage: true}
YAML
  chown root:picket /etc/picket/agent.yaml
  chmod 0640 /etc/picket/agent.yaml
fi
if [ "$UPGRADE" -eq 0 ]; then
  umask 077
  printf '%s' "$TOKEN" > /etc/picket/token
  chown root:picket /etc/picket/token
  chmod 0600 /etc/picket/token
fi

# --- download + verify + install the binary --------------------------
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "fetching $BIN from $RELEASE_BASE"
curl -fsSL "$RELEASE_BASE/$BIN"       -o "$tmp/$BIN"
curl -fsSL "$RELEASE_BASE/$BIN.sig"   -o "$tmp/$BIN.sig"
curl -fsSL "$RELEASE_BASE/SHA256SUMS" -o "$tmp/SHA256SUMS"

want="$(grep -E "  ${BIN}\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
got="$(sha256sum "$tmp/$BIN" | awk '{print $1}')"
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "SHA256 mismatch for $BIN" >&2; exit 1; }

PUB="$(dirname "$0")/cosign.pub"
if command -v cosign >/dev/null 2>&1 && [ -f "$PUB" ] && ! grep -q PLACEHOLDER "$PUB"; then
  cosign verify-blob --key "$PUB" --signature "$tmp/$BIN.sig" "$tmp/$BIN"
else
  echo "WARNING: cosign signature NOT verified (cosign missing or cosign.pub is a placeholder)" >&2
fi

install -o picket -g picket -m 0755 "$tmp/$BIN" /var/lib/picket/bin/picket-agent.new
mv -f /var/lib/picket/bin/picket-agent.new /var/lib/picket/bin/picket-agent
ln -sf /var/lib/picket/bin/picket-agent /usr/local/bin/picket-agent

# --- systemd ---------------------------------------------------------
install -m 0644 "$(dirname "$0")/picket-agent.service" /etc/systemd/system/picket-agent.service
systemctl daemon-reload
systemctl enable --now picket-agent
systemctl restart picket-agent
systemctl --no-pager status picket-agent | head -5 || true
