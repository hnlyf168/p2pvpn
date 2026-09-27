@echo off
REM 以管理员权限安装并启动 Windows Edge VPN 客户端服务。
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~dp0P2PVpnClient.exe' -ArgumentList 'install' -Verb RunAs -Wait"
pause
