param([string]$Package = 'artifacts/downloads/edge-vpn-client-win-x64-0.3.0.zip')
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$target = Join-Path $workspace ('artifacts/package-check/' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $target | Out-Null
Expand-Archive -LiteralPath (Join-Path $workspace $Package) -DestinationPath $target
if (!(Test-Path -LiteralPath (Join-Path $target 'wintun.dll'))) { throw 'wintun.dll is missing from package' }
$profile = @{server = '127.0.0.1:49000'; group = 'package-smoke-test'; sharedSecret = 'a-configuration-validation-secret-2026'; deviceId = 'package-smoke-test'; deviceToken = 'not-a-real-device-token'; relayUrls = @(); enableAutoUpdate = $false}
$profile | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'client.json') -Encoding UTF8
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = Join-Path $target 'P2PVpnClient.exe'
$info.Arguments = 'check'; $info.WorkingDirectory = $target
$info.UseShellExecute = $false; $info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
$info.EnvironmentVariables['DOTNET_ROOT'] = Join-Path $target 'no-installed-runtime'
$child = [Diagnostics.Process]::Start($info)
$output = $child.StandardOutput.ReadToEnd(); $errorText = $child.StandardError.ReadToEnd(); $child.WaitForExit()
if ($child.ExitCode -ne 0) { throw "Packaged client check failed: $errorText" }
Write-Host $output
Add-Type -TypeDefinition '
using System;
using System.Runtime.InteropServices;
public static class EdgePackageNativeCheck {
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32", CharSet=CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32")] public static extern bool FreeLibrary(IntPtr module);
}'
$module = [EdgePackageNativeCheck]::LoadLibrary((Join-Path $target 'wintun.dll'))
if ($module -eq [IntPtr]::Zero) { throw 'Cannot load packaged Wintun library' }
try {
    foreach ($symbol in @('WintunCreateAdapter','WintunStartSession','WintunReceivePacket','WintunSendPacket')) {
        if ([EdgePackageNativeCheck]::GetProcAddress($module, $symbol) -eq [IntPtr]::Zero) { throw "Missing export: $symbol" }
    }
} finally { [EdgePackageNativeCheck]::FreeLibrary($module) | Out-Null }
Write-Host 'PASS: standalone Windows executable, valid config, packaged Wintun library and required exports. No adapter created.'
