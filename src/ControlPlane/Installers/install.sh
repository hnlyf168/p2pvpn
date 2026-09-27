#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
control='__CONTROL_URL__'
ticket='__INSTALL_TICKET__'
mode=install
fail() { printf '%s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ticket) [ "$#" -ge 2 ] || fail 'Missing ticket'; ticket=$2; shift 2 ;;
        --download-only) mode=download; shift ;;
        --configure-only) mode=configure; shift ;;
        *) fail "Unknown option: $1" ;;
    esac
done
[ "$mode" = download ] || [ "$(id -u)" = 0 ] || fail 'Please run this script with sudo.'
if ! command -v unzip >/dev/null 2>&1 && command -v busybox >/dev/null 2>&1; then
    if busybox --list | grep -qx unzip; then unzip() { busybox unzip "$@"; }; fi
fi
for tool in curl unzip sha256sum awk df stat od dd tr uname mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "Missing dependency: $tool"
done
# Read the executing shell's ELF class: kernel architecture alone does not identify userspace bitness.
elf=/proc/$$/exe
[ -r "$elf" ] || elf=/bin/sh
elf_class=$(od -An -tu1 -j4 -N1 "$elf" | tr -d ' \n')
machine=$(uname -m)
case "$machine:$elf_class" in
    x86_64:2|amd64:2) platform=linux-x64 ;;
    aarch64:2|arm64:2) platform=linux-arm64 ;;
    armv7*:1|armv8*:1|aarch64:1|arm64:1) platform=linux-arm ;;
    i?86:*|x86:*|x86_64:1|amd64:1) fail 'Linux x86 32-bit is unsupported; ARM32 is a different architecture. No installation ticket was consumed.' ;;
    *) fail "Unsupported architecture: $machine (ELF class $elf_class). Available: x64, ARM64, ARMv7." ;;
esac
printf 'Detected client platform: %s\n' "$platform"
# Rendered from the platform catalog; these values are data, never downloaded shell code.
case "$platform" in
    linux-x64) package='__LINUX_X64_PATH__'; expected='__LINUX_X64_SHA256__' ;;
    linux-arm64) package='__LINUX_ARM64_PATH__'; expected='__LINUX_ARM64_SHA256__' ;;
    linux-arm) package='__LINUX_ARM_PATH__'; expected='__LINUX_ARM_SHA256__' ;;
esac
case "$expected" in ''|*[!a-f0-9]*) fail 'No verified package available for this platform.' ;; esac
[ "${#expected}" = 64 ] || fail 'Invalid package checksum.'
if [ "$mode" = install ]; then
    command -v ip >/dev/null || fail 'Install iproute2 first.'
    command -v systemctl >/dev/null || fail 'This installer requires systemd.'
    [ -c /dev/net/tun ] || fail '/dev/net/tun is unavailable.'
fi
umask 077
stage=/tmp
transient=
lock=
if [ -n "$ticket" ] && [ "$mode" != download ]; then
    case "$ticket" in *[!A-Za-z0-9_-]*) fail 'Invalid ticket' ;; esac
    [ "${#ticket}" = 43 ] || fail 'Invalid ticket'
    fingerprint=$(printf '%s' "$ticket" | sha256sum | awk '{print $1}')
    stage=/var/lib/edge-vpn-setup/$fingerprint
fi
# BEGIN STORAGE CHECK
storage_row() {
    target=$1; parent=$target
    while [ ! -e "$parent" ]; do parent=${parent%/*}; [ -n "$parent" ] || parent=/; done
    [ -w "$parent" ] || fail "Storage is read-only or not writable: $parent"
    device=$(stat -c '%d' "$parent") || exit 1
    available=$(df -Pk "$parent" | awk 'NR==2 {print $(NF-2)}')
    inodes=$(df -Pi "$parent" | awk 'NR==2 {if($(NF-4)==0) print "-"; else print $(NF-2)}')
    case "$available" in ''|*[!0-9]*) fail "Cannot inspect free space: $parent" ;; esac
    printf '%s %s %s %s %s %s\n' "$device" "$2" "$3" "$available" "${inodes:--}" "$target"
}
rows=$(
    storage_row "$stage" 65536 64 || exit 1
    if [ "$mode" != download ]; then
        storage_row /opt/edge-vpn 32768 64 || exit 1
        storage_row /var/lib/edge-vpn 8192 32 || exit 1
        storage_row /etc/systemd/system 1024 8 || exit 1
    fi
) || fail 'Cannot inspect installation storage; no ticket redeemed.'
printf '%s\n' "$rows" | awk '
    { d=$1; needed[d]+=$2; nodes[d]+=$3; free[d]=$4; if($5 ~ /^[0-9]+$/) inode[d]=$5; paths[d]=paths[d] " " $6 }
    END { for(d in needed) {
        if(free[d]<needed[d]+16384) { printf "Insufficient space:%s: %.1f MiB available; %.1f MiB needed\n",paths[d],free[d]/1024,(needed[d]+16384)/1024; bad=1 }
        if(d in inode && inode[d]<nodes[d]+16) { printf "Insufficient free inodes:%s\n",paths[d]; bad=1 }
    } exit bad }
' || fail 'Installation stopped before redeeming a ticket. Inspect: df -h / /var/lib /opt /tmp; df -i / /var/lib /opt /tmp. Free space or expand the affected filesystem and retry.'
# END STORAGE CHECK
if [ "$stage" = /tmp ]; then
    stage=$(mktemp -d /tmp/edge-vpn-setup.XXXXXXXX)
    transient=$stage
else
    mkdir -p "$stage"
    chmod 700 /var/lib/edge-vpn-setup "$stage"
fi
cleanup() {
    if [ -n "$lock" ]; then
        rm -f -- "$stage/redeem.request" "$stage/client/client.json.tmp" "$stage/claim.txt.tmp"
        rmdir -- "$lock" 2>/dev/null || :
    fi
    [ -z "$transient" ] || rm -rf -- "$transient"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM
mkdir "$stage/.lock" 2>/dev/null || fail "Another installation is using $stage. If it was interrupted, verify it has stopped before removing $stage/.lock."
lock=$stage/.lock
if [ -n "$ticket" ] && [ "$mode" != download ] && [ -f /opt/edge-vpn/client.json ]; then
    [ -f "$stage/client/client.json" ] || fail 'A device is already installed. Use the generic installer to upgrade; this ticket has not been consumed.'
fi
curl -fsS --connect-timeout 15 --max-time 180 "$control$package" -o "$stage/client.zip"
printf '%s  %s\n' "$expected" "$stage/client.zip" | sha256sum -c - >/dev/null || fail 'SHA-256 mismatch; installation stopped.'
mkdir -p "$stage/client"
# Extract fixed members to fixed paths; ZIP paths and symlinks cannot choose an extraction destination.
for member in P2PVpnClient install-linux.sh uninstall-linux.sh README.md client.example.json; do
    unzip -p "$stage/client.zip" "$member" > "$stage/client/$member.tmp" || fail "Missing package member: $member"
    mv "$stage/client/$member.tmp" "$stage/client/$member"
done
printf '%s\n' 'Client downloaded and SHA-256 verified.'
cd "$stage/client"
chmod 755 P2PVpnClient
./P2PVpnClient version || fail 'Client runtime could not start; no installation ticket was redeemed by this attempt.'
[ "$mode" != download ] || exit 0
if [ -n "$ticket" ] && [ -f /opt/edge-vpn/client.json ]; then
    installed_id=$(/opt/edge-vpn/P2PVpnClient id)
    cached_id=$(./P2PVpnClient id)
    [ -n "$installed_id" ] && [ "$installed_id" = "$cached_id" ] || fail 'A different VPN device is installed; back it up and uninstall it first.'
fi
# BEGIN ENROLLMENT
if [ -n "$ticket" ]; then
    if [ ! -f "$stage/claim.txt" ]; then
        dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n' > "$stage/claim.txt.tmp"
        [ "$(wc -c < "$stage/claim.txt.tmp" | tr -d ' ')" = 64 ] || fail 'Could not generate secure installation claim.'
        mv "$stage/claim.txt.tmp" "$stage/claim.txt"
    fi
    claim=$(cat "$stage/claim.txt")
    case "$claim" in *[!A-Za-z0-9_-]*) fail 'Invalid local installation claim' ;; esac
    [ "${#claim}" -ge 43 ] && [ "${#claim}" -le 64 ] || fail 'Invalid local installation claim'
    printf '{"claim":"%s","platform":"%s"}' "$claim" "$platform" > "$stage/redeem.request"
    # Keep the ticket out of curl arguments, URLs and on-disk request files.
    status=$(printf 'header = "Authorization: Bearer %s"\n' "$ticket" | curl --config - -sS --connect-timeout 15 --max-time 45 -H 'Content-Type: application/json' --data-binary "@$stage/redeem.request" -o "$stage/client/client.json.tmp" -w '%{http_code}' "$control/api/install/redeem") || fail 'Enrollment request failed. Retry the same command on this machine.'
    rm -f -- "$stage/redeem.request"
    case "$status" in
        200) mv "$stage/client/client.json.tmp" "$stage/client/client.json" ;;
        401) fail 'Installation command expired, revoked or used by another device. Generate a new command in the console.' ;;
        429) fail 'Too many requests; wait and retry the same command.' ;;
        *) fail "Enrollment failed (HTTP $status). Check the console for device limits and network status." ;;
    esac
    printf '%s\n' 'Device identity and network configuration saved automatically.'
# END ENROLLMENT
elif [ -f /opt/edge-vpn/client.json ]; then
    cp /opt/edge-vpn/client.json client.json
    printf '%s\n' 'Existing device identity, control server and network configuration will be preserved.'
else
    ./P2PVpnClient join "$control" </dev/tty
fi
./P2PVpnClient check
[ "$mode" != configure ] || { printf 'Configuration verified in %s; system service unchanged.\n' "$stage/client"; exit 0; }
sh install-linux.sh
systemctl restart edge-vpn
systemctl --no-pager status edge-vpn
# Retain the small profile/claim for retries; discard only this installer's large cache files.
rm -f -- "$stage/client.zip" "$stage/client/P2PVpnClient"
printf '%s\n' 'Installation complete. Download cache removed. Return to the console to see the device come online.'
