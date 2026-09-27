#!/bin/sh
# 停止并卸载 Linux 版 Edge VPN 客户端。
set -eu
test "$(id -u)" = "0" || { echo "请使用 root 运行卸载脚本"; exit 1; }
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now edge-vpn.service 2>/dev/null || true
  rm -f /etc/systemd/system/edge-vpn.service
  systemctl daemon-reload
elif test -x /etc/init.d/edge-vpn; then
  /etc/init.d/edge-vpn stop || true
  rm -f /etc/init.d/edge-vpn
fi
rm -rf /opt/edge-vpn
echo "程序已卸载；设备 ID 和日志仍保留在 /var/lib/edge-vpn"
