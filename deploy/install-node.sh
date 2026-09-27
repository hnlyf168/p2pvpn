#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run with sudo sh install-node.sh'; exit 1; }
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
[ -f node.env ] || { echo 'Download node.env from the operator console first.'; exit 1; }
role=$(sed -n 's/^Role=//p' node.env | tr -d '\r')
case "$role" in punch|relay) ;; *) echo 'Invalid Role in node.env'; exit 1;; esac
[ "$(cat package-role)" = "$role" ] || { echo 'Configuration does not match this package role.'; exit 1; }
grep -q '^NodeId=.' node.env && grep -q '^NodeKey=.' node.env || { echo 'Missing registered node credentials'; exit 1; }
unit="edge-vpn-$role"
release="/opt/$unit/releases/$(date -u +%Y%m%d%H%M%S)"
id "$unit" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$unit"
install -d -m 755 "$release" "/etc/$unit"
cp -R bin/. "$release/"
chmod 755 "$release/EdgeVpn.Node"
install -m 600 node.env "/etc/$unit/node.env"
cat > "/etc/systemd/system/$unit.service" <<EOF
[Unit]
Description=Edge VPN $role node
After=network-online.target
Wants=network-online.target
[Service]
User=$unit
Group=$unit
WorkingDirectory=$release
ExecStart=$release/EdgeVpn.Node
EnvironmentFile=/etc/$unit/node.env
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65535
MemoryMax=768M
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$unit"
systemctl restart "$unit"
sleep 2
systemctl --no-pager --full status "$unit"
echo 'Complete TLS/proxy setup for relay, or TCP+UDP coordinator firewall rules for punch. See README.md.'
