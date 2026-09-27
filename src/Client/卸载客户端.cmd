@echo off
REM 停止并卸载 Windows Edge VPN 客户端服务。
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~dp0P2PVpnClient.exe' -ArgumentList 'uninstall' -Verb RunAs -Wait"
pause
