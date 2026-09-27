#!/bin/sh
# 安装 Linux 版 Edge VPN 客户端及其系统服务。
set -eu
test "$(id -u)" = "0" || { echo "请使用 root 运行安装脚本"; exit 1; }
test -f ./P2PVpnClient || { echo "当前目录缺少 P2PVpnClient"; exit 1; }
test -f ./client.json || { echo "当前目录缺少 client.json"; exit 1; }
install -d -m 700 "/opt/edge-vpn" "/var/lib/edge-vpn"
cp -R ./* "/opt/edge-vpn/"
chmod -R go-rwx "/opt/edge-vpn"
chmod 755 "/opt/edge-vpn/P2PVpnClient"
install -m 600 ./client.json "/opt/edge-vpn/client.json"
if [ -n "${P2P_NETWORK_MODE:-}" ]; then
  /opt/edge-vpn/P2PVpnClient network-mode "$P2P_NETWORK_MODE"
fi
if command -v systemctl >/dev/null 2>&1; then
  printf '%s\n' '[Unit]' 'Description=Edge VPN Client' 'After=network-online.target' 'Wants=network-online.target' '' '[Service]' 'Type=simple' 'ExecStart=/opt/edge-vpn/P2PVpnClient' 'Restart=always' 'RestartSec=5' 'AmbientCapabilities=CAP_NET_ADMIN' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/edge-vpn.service
  systemctl daemon-reload
  systemctl enable --now edge-vpn.service
elif test -d /etc/init.d; then
  printf '%s\n' '#!/bin/sh' 'case "$1" in' ' start) start-stop-daemon -S -b -m -p /var/run/edge-vpn.pid -x /opt/edge-vpn/P2PVpnClient ;;' ' stop) start-stop-daemon -K -p /var/run/edge-vpn.pid ;;' ' restart) "$0" stop; "$0" start ;;' 'esac' > /etc/init.d/edge-vpn
  chmod 755 /etc/init.d/edge-vpn
  /etc/init.d/edge-vpn restart
else
  echo "未识别服务管理器，请手动运行 /opt/edge-vpn/P2PVpnClient"
fi
echo "Edge VPN 客户端已安装到 /opt/edge-vpn"
