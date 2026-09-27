param([string[]]$Runtimes = @('win-x64', 'linux-x64', 'linux-arm64', 'linux-arm'), [string]$Version = '0.3.3')
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    $downloads = Join-Path $workspace 'artifacts/downloads'
    $releaseRoot = Join-Path $workspace ('artifacts/releases/' + $Version)
    New-Item -ItemType Directory -Force -Path $downloads,$releaseRoot,'src/ControlPlane/downloads' | Out-Null
    foreach ($runtime in $Runtimes) {
        if ($runtime -notin @('win-x64','win-x86','linux-x64','linux-arm64','linux-arm')) { throw "Unsupported runtime: $runtime" }
        $output = Join-Path $releaseRoot "client-$runtime"
        if ($runtime.StartsWith('linux-')) {
            if (!(Test-Path -LiteralPath "$output/P2PVpnClient")) { throw "Build Linux clients on the designated native builders first (tools/build-native-clients.sh), then fetch and verify with tools/package-native-clients.py." }
            python tools/verify-native-elf.py "$output/P2PVpnClient" $runtime
            if ($LASTEXITCODE -ne 0) { throw "Linux package is not a verified static NativeAOT binary: $runtime" }
        } else {
            dotnet publish src/Client/P2PVpnClient.csproj -c Release -r $runtime --self-contained true -p:PublishAot=true -p:PublishSingleFile=false -o $output --nologo -v quiet
            if ($LASTEXITCODE -ne 0) { throw "Native publish failed: $runtime" }
        }
        $zip = Join-Path $downloads "edge-vpn-client-$runtime-$Version.zip"
        $files = Get-ChildItem -LiteralPath $output -File | Where-Object { $_.Name -ne 'client.json' -and $_.Extension -ne '.pdb' }
        python tools/zip-package.py $output $zip --client
        if ($LASTEXITCODE -ne 0) { throw "Client archive failed" }
    }
    $node = Join-Path $releaseRoot 'node-linux-x64'
    dotnet publish src/Node/EdgeVpn.Node.csproj -c Release -r linux-x64 --self-contained true -p:DebugType=None -o $node --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Node publish failed' }
    foreach ($role in @('punch','relay')) {
        $stage = Join-Path $releaseRoot $role
        New-Item -ItemType Directory -Force -Path "$stage/bin" | Out-Null
        Copy-Item -Path "$node/*" -Destination "$stage/bin/" -Recurse -Force
        [IO.File]::WriteAllText("$stage/package-role", $role, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText("$stage/install-node.sh", (Get-Content deploy/install-node.sh -Raw -Encoding UTF8).Replace("`r`n","`n"), [Text.UTF8Encoding]::new($false))
        Copy-Item deploy/NODE-README.md "$stage/README.md" -Force
        python tools/zip-package.py $stage "$downloads/edge-vpn-$role-linux-x64-$Version.zip"
        if ($LASTEXITCODE -ne 0) { throw "Node archive failed" }
    }
    $control = Join-Path $releaseRoot 'control-linux-x64'
    dotnet publish src/ControlPlane/EdgeVpn.ControlPlane.csproj -c Release -r linux-x64 --self-contained true -p:DebugType=None -o $control --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Control publish failed' }
    $controlPackage = Join-Path $releaseRoot 'control-package'
    New-Item -ItemType Directory -Force -Path "$controlPackage/bin","$controlPackage/deploy" | Out-Null
    $files = Get-ChildItem -LiteralPath $control | Where-Object { $_.Name -notin @('downloads','data') }
    foreach ($item in $files) { Copy-Item -LiteralPath $item.FullName -Destination "$controlPackage/bin" -Recurse -Force }
    Copy-Item -Path 'deploy/control.env.example','deploy/edge-vpn-control.service','deploy/nginx.conf' -Destination "$controlPackage/deploy" -Force
    Copy-Item docs/DEPLOYMENT.md "$controlPackage/README.md" -Force
    python tools/zip-package.py $controlPackage "$downloads/edge-vpn-control-linux-x64-$Version.zip"
    if ($LASTEXITCODE -ne 0) { throw "Control archive failed" }
    New-Item -ItemType Directory -Force -Path "$control/downloads" | Out-Null
    $packages = Get-ChildItem -LiteralPath $downloads -Filter "*-$Version.zip"
    $hashes = foreach ($package in $packages) {
        Copy-Item -LiteralPath $package.FullName -Destination 'src/ControlPlane/downloads/' -Force
        Copy-Item -LiteralPath $package.FullName -Destination "$control/downloads/" -Force
        (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $package.Name
    }
    [IO.File]::WriteAllLines("$downloads/SHA256SUMS-$Version.txt", $hashes, [Text.UTF8Encoding]::new($false))
    Write-Host "Published $($packages.Count) packages to $downloads"
} finally { Pop-Location }
