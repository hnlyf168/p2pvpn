param([switch]$DownloadOnly, [switch]$ConfigureOnly, [string]$Destination = '', [string]$Ticket = '__INSTALL_TICKET__')
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$control = '__CONTROL_URL__'
if ($ConfigureOnly -and !$Destination) { throw 'ConfigureOnly requires an explicit destination.' }
if ($Ticket -and $Ticket -notmatch '^[A-Za-z0-9_-]{43}$') { throw 'Invalid installation ticket.' }
if (!$DownloadOnly -and !$ConfigureOnly) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (!(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '请使用官网的一键安装.cmd，或在管理员 PowerShell 中运行。' }
}
if (![Environment]::Is64BitOperatingSystem) { throw '当前一键安装包支持 Windows x64。' }
if (!$Destination -and $Ticket -and !$DownloadOnly) {
    $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Ticket))).Replace('-', '')
    $Destination = Join-Path $env:ProgramFiles ('Edge VPN Setup/' + $hash)
}
if (!$Destination) { $Destination = Join-Path $env:TEMP ('EdgeVpnSetup-' + [Guid]::NewGuid().ToString('N')) }
$stage = [IO.Path]::GetFullPath($Destination)
if ((Test-Path -LiteralPath $stage) -and !$Ticket) { throw '安装暂存目录已存在，请使用新的目录。' }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $stage /inheritance:r /grant:r "*${owner}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法保护安装暂存目录。' }
$previous = Join-Path $env:ProgramFiles 'Edge VPN/client.json'
$cachedProfile = Join-Path $stage 'client/client.json'
if ($Ticket -and !$DownloadOnly -and !$ConfigureOnly -and (Test-Path -LiteralPath $previous)) {
    $old = Get-Content -LiteralPath $previous -Raw -Encoding UTF8 | ConvertFrom-Json
    if (!(Test-Path -LiteralPath $cachedProfile)) { throw '本机已有 VPN 设备。请使用通用脚本升级；如需加入新网络，请先备份并卸载旧客户端。新命令尚未使用。' }
    $cached = Get-Content -LiteralPath $cachedProfile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($old.deviceId -ne $cached.deviceId) { throw '本机已有不同设备身份，请先备份并卸载旧客户端。' }
}
Write-Host '正在下载并校验客户端，请稍候…'
$catalog = Invoke-RestMethod -Uri "$control/api/downloads"
$package = $catalog | Where-Object { $_.kind -eq 'client' -and $_.platform -eq 'win-x64' } | Select-Object -First 1
if (!$package -or $package.url -notmatch '^/downloads/edge-vpn-client-win-x64-[0-9.]+\.zip$') { throw '没有可用的 Windows 客户端安装包。' }
$archive = Join-Path $stage 'client.zip'
Invoke-WebRequest -UseBasicParsing -Uri ($control + $package.url) -OutFile $archive
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $package.sha256) { throw '文件校验失败，已停止安装。' }
$bin = Join-Path $stage 'client'
Expand-Archive -LiteralPath $archive -DestinationPath $bin -Force
if ($DownloadOnly) { Write-Host "下载及 SHA-256 校验成功：$bin"; return }
$previous = Join-Path $env:ProgramFiles 'Edge VPN/client.json'
if ($Ticket) {
    $claimFile = Join-Path $stage 'claim.txt'
    if (!(Test-Path -LiteralPath $claimFile)) {
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($bytes); $rng.Dispose()
        $claim = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        [IO.File]::WriteAllText($claimFile, $claim)
    }
    $claim = [IO.File]::ReadAllText($claimFile)
    $body = @{claim=$claim; platform='win-x64'} | ConvertTo-Json -Compress
    try {
        $profile = Invoke-RestMethod -Method Post -Uri "$control/api/install/redeem" -Headers @{Authorization="Bearer $Ticket"} -ContentType 'application/json' -Body $body
    } catch { throw '自动加网未完成：命令可能过期、已在其他设备使用，或网络已满。请返回控制台查看状态并重新生成。' }
    [IO.File]::WriteAllText((Join-Path $bin 'client.json'), ($profile | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
    Write-Host '设备身份与网络配置已自动写入。'
} elseif (Test-Path -LiteralPath $previous) {
    $settings = Get-Content -LiteralPath $previous -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($settings.controlUrl.TrimEnd('/') -ne $control) { throw '已有其他平台的设备配置，请先备份并卸载旧客户端。' }
    Copy-Item -LiteralPath $previous -Destination (Join-Path $bin 'client.json')
    Write-Host '检测到已安装设备，将保留身份与网络配置升级。'
} else {
    & (Join-Path $bin 'P2PVpnClient.exe') join $control
    if ($LASTEXITCODE -ne 0) { throw '加入网络失败，尚未安装服务。请检查加入码有效期和剩余次数。' }
}
& (Join-Path $bin 'P2PVpnClient.exe') check
if ($LASTEXITCODE -ne 0) { throw '配置检查失败。' }
if ($ConfigureOnly) { Write-Host "配置与程序校验完成（未安装服务）：$bin"; return }
& (Join-Path $bin 'P2PVpnClient.exe') install
if ($LASTEXITCODE -ne 0) { throw '安装失败，请检查窗口提示。' }
# The validated per-run staging directory contains only this installer run's files.
$resolved = (Resolve-Path -LiteralPath $stage).Path
if ($resolved -eq $stage -and (Split-Path -Leaf $stage) -like 'EdgeVpnSetup-*') { Remove-Item -LiteralPath $stage -Recurse -Force }
Write-Host '安装完成，客户端服务会开机自动连接。返回网页即可查看上线状态。'
# Keep the protected retry identity until this 30-minute command expires; no credential is printed.
