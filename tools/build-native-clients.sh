#!/bin/sh
set -eu
host_role="$1"
workspace=/root/edge-vpn-native-0.3.3
mkdir -p "$workspace"
tar -xzf /root/edge-vpn-native-0.3.3-source.tar.gz -C "$workspace"
cd "$workspace"
build() {
 rid="$1"; image="$2"; cache="$3"
 echo "Building $rid on $(uname -m) with $image"
 extra=''
 [ "$rid" != linux-musl-arm ] || extra='-p:UseSystemZlib=true'
 docker run --rm --cpus=3 --memory=3g --entrypoint dotnet -v "$workspace:/src" -v "$cache:/root/.nuget/packages" -w /src "$image" publish src/Client/P2PVpnClient.csproj -c Release -r "$rid" -p:PublishAot=true -p:StaticExecutable=true -p:StaticOpenSslLinking=true -p:StripSymbols=true -p:CppCompilerAndLinker=clang -p:NuGetAudit=false $extra -o "/src/out/$rid" -v:minimal
 binary="out/$rid/P2PVpnClient"
 file "$binary"
 if readelf -l "$binary" | grep -q INTERP; then echo 'FAIL: dynamic interpreter present'; exit 1; fi
 if readelf -d "$binary" | grep -q NEEDED; then echo 'FAIL: dynamic library dependency present'; exit 1; fi
 "$binary" version
 sha256sum "$binary"
 tar -czf "$rid.tar.gz" -C "out/$rid" .
}
if [ "$host_role" = arm ]; then
 build linux-musl-arm64 p2p-aot-sdk:arm64-lld /root/nuget-cache-arm64
 build linux-musl-arm p2p-aot-sdk:arm32-static /root/nuget-cache-arm32
else
 build linux-musl-x64 p2pvpn-builder-x64:10 /root/.nuget/packages
fi
printf 'SUCCESS\n' > "$workspace/complete-$host_role"
