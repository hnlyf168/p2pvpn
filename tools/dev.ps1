param([int]$Port = 5080, [int]$RelayPort = 5081)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    dotnet build EdgeVpn.sln -c Release --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    $dev = Join-Path $workspace 'artifacts/dev'
    New-Item -ItemType Directory -Force -Path $dev | Out-Null
    $secretPath = Join-Path $dev 'secrets.json'
    if (!(Test-Path -LiteralPath $secretPath)) {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $secrets = @{}
        foreach ($name in @('AdminKey','PunchNodeKey','RelayNodeKey')) {
            $bytes = New-Object byte[] 32; $rng.GetBytes($bytes); $secrets[$name] = [Convert]::ToBase64String($bytes)
        }
        $rng.Dispose()
        $secrets | ConvertTo-Json | Set-Content -LiteralPath $secretPath -Encoding UTF8
    }
    $secrets = Get-Content -LiteralPath $secretPath -Raw | ConvertFrom-Json
    foreach ($listenPort in @($Port, $RelayPort)) {
        $probe = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback, $listenPort)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    $processes = @()
    foreach ($role in @('ControlPlane','Node')) {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = 'dotnet'
        $info.WorkingDirectory = Join-Path $workspace "src/$role"
        $assembly = if ($role -eq 'ControlPlane') { 'EdgeVpn.ControlPlane.dll' } else { 'EdgeVpn.Node.dll' }
        $info.Arguments = '"' + (Join-Path $info.WorkingDirectory "bin/Release/net10.0/$assembly") + '"'
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        if ($role -eq 'ControlPlane') {
            $info.EnvironmentVariables['ASPNETCORE_ENVIRONMENT'] = 'Development'
            $info.EnvironmentVariables['Mail__PickupDirectory'] = Join-Path $dev 'mail'
            $info.EnvironmentVariables['ASPNETCORE_URLS'] = "http://127.0.0.1:$Port"
            $info.EnvironmentVariables['PublicUrl'] = "http://localhost:$Port"
            $info.EnvironmentVariables['DataDirectory'] = Join-Path $dev 'data'
            $info.EnvironmentVariables['AdminKey'] = $secrets.AdminKey
            $info.EnvironmentVariables['PunchNodeKey'] = $secrets.PunchNodeKey
            $info.EnvironmentVariables['RelayNodeKey'] = $secrets.RelayNodeKey
            $info.EnvironmentVariables['RelayUrls__0'] = "ws://localhost:$RelayPort/relay"
        } else {
            $info.EnvironmentVariables['ASPNETCORE_URLS'] = "http://127.0.0.1:$RelayPort"
            $info.EnvironmentVariables['Role'] = 'relay'
            $info.EnvironmentVariables['ControlUrl'] = "http://localhost:$Port"
            $info.EnvironmentVariables['NodeKey'] = $secrets.RelayNodeKey
        }
        $names = @('ASPNETCORE_ENVIRONMENT','Mail__PickupDirectory','ASPNETCORE_URLS','PublicUrl','DataDirectory','AdminKey','PunchNodeKey','RelayNodeKey','RelayUrls__0','Role','ControlUrl','NodeKey')
        $previous = @{}
        try {
            foreach ($name in $names) {
                $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
                [Environment]::SetEnvironmentVariable($name, $info.EnvironmentVariables[$name], 'Process')
            }
            $child = Start-Process -FilePath 'dotnet' -ArgumentList $info.Arguments -WorkingDirectory $info.WorkingDirectory -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dev "$role.out.log") -RedirectStandardError (Join-Path $dev "$role.err.log") -PassThru
        } finally {
            foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
        }
        $processes += @{ role = $role; pid = $child.Id }
    }
    Start-Sleep -Seconds 2
    foreach ($child in $processes) { if (!(Get-Process -Id $child.pid -ErrorAction SilentlyContinue)) { throw "Startup failed: $($child.role)" } }
    $processes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dev 'processes.json') -Encoding UTF8
    Write-Host "Control panel: http://localhost:$Port"
    Write-Host "Local administrator secrets: $secretPath"
    Write-Host "Development verification emails: $dev/mail (local development only)"
    Write-Host "To stop: powershell -File tools/stop-dev.ps1"
} finally { Pop-Location }
