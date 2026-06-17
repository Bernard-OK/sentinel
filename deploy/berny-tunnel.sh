#!/usr/bin/env bash
# Install + start the permanent Cloudflare named tunnel for Sentinel as a boot service.
#
# Prereqs (one-time, interactive — already done on Berny):
#   cloudflared tunnel login              # authorizes the okwampah.com zone → cert.pem
#   cloudflared tunnel create sentinel    # creates the tunnel + credentials json
#
# Then just run:  bash deploy/berny-tunnel.sh
set -euo pipefail

TUNNEL=sentinel
HOSTNAME=sentinel.okwampah.com
CFDIR="$HOME/.cloudflared"
SRC="$(cd "$(dirname "$0")" && pwd)/cloudflared/config.yml"
CF="$(command -v cloudflared)"

[ -n "$CF" ] || { echo "cloudflared not found on PATH"; exit 1; }
[ -f "$CFDIR/cert.pem" ] || { echo "No $CFDIR/cert.pem — run 'cloudflared tunnel login' first"; exit 1; }

echo "==> Installing tunnel config to $CFDIR/config.yml"
mkdir -p "$CFDIR"
cp "$SRC" "$CFDIR/config.yml"
cat "$CFDIR/config.yml"

echo "==> Creating DNS route $HOSTNAME (ok if it already exists)"
"$CF" tunnel route dns "$TUNNEL" "$HOSTNAME" || true

echo "==> Installing systemd service"
sudo tee /etc/systemd/system/cloudflared-sentinel.service >/dev/null <<EOF
[Unit]
Description=cloudflared tunnel (sentinel)
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
ExecStart=$CF --no-autoupdate tunnel run $TUNNEL
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cloudflared-sentinel
sleep 4
sudo systemctl status cloudflared-sentinel --no-pager | head -8

echo
echo "==> Verifying https://$HOSTNAME/health"
sleep 4
curl -s "https://$HOSTNAME/health" && echo
echo "Done. If you see {\"status\":\"ok\"...} above, Sentinel is permanently live at https://$HOSTNAME"
