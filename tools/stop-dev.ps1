$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$path = Join-Path $workspace 'artifacts/dev/processes.json'
if (!(Test-Path -LiteralPath $path)) { Write-Host 'No recorded development processes.'; exit 0 }
$entries = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
foreach ($entry in $entries) {
    if ($entry.role -notin @('ControlPlane','Node')) { throw 'Unexpected recorded process role.' }
    $assembly = if ($entry.role -eq 'ControlPlane') { 'EdgeVpn.ControlPlane.dll' } else { 'EdgeVpn.Node.dll' }
    $expected = Join-Path $workspace ("src/" + $entry.role + "/bin/Release/net10.0/" + $assembly)
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId = " + [int]$entry.pid)
    if ($process -and $process.CommandLine -and $process.CommandLine.Contains($expected)) {
        Stop-Process -Id ([int]$entry.pid)
        Write-Host ("Stopped " + $entry.role)
    } elseif ($process) {
        throw "Recorded PID now belongs to a different process; refusing to stop it."
    }
}
'[]' | Set-Content -LiteralPath $path -Encoding UTF8
