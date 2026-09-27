#!/usr/bin/env python3
"""Run only on the Android CI builder; package and verify the signed APK."""
from pathlib import Path
import os, re, shutil, subprocess, xml.etree.ElementTree as ET, zipfile, hashlib

root = Path(__file__).resolve().parents[1]
project = ET.parse(root / "src/Android/P2PVpnAndroid.csproj")
version = project.findtext(".//ApplicationDisplayVersion")
code = project.findtext(".//ApplicationVersion")
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
packages = list((root / "artifacts/android-build").glob("*-Signed.apk"))
assert len(packages) == 1, "Expected exactly one signed, universal APK"
tools = Path(os.environ["ANDROID_HOME"]) / "build-tools"
sdk = sorted((p for p in tools.iterdir() if (p / "apksigner").exists()), key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)])[-1]
signature = subprocess.check_output([str(sdk / "apksigner"), "verify", "--verbose", "--print-certs", str(packages[0])], text=True)
fingerprint = (root / "src/Android/signing-certificate.sha256").read_text().strip()
assert ("certificate SHA-256 digest: " + fingerprint) in signature, "Unexpected signing certificate"
assert "Android Debug" not in signature, "Debug signing is forbidden"
manifest = subprocess.check_output([str(sdk / "aapt"), "dump", "badging", str(packages[0])], text=True)
assert "package: name='pub.hngs.vpn'" in manifest and f"versionCode='{code}'" in manifest and f"versionName='{version}'" in manifest
assert "sdkVersion:'26'" in manifest
assert "application-debuggable" not in manifest
with zipfile.ZipFile(packages[0]) as apk:
    names = apk.namelist()
    abis = {p.split("/")[1] for p in names if p.startswith("lib/") and p.endswith(".so")}
    assert abis == {"armeabi-v7a", "arm64-v8a", "x86_64"}, abis
    assert not any(p.lower().endswith((".p12", ".jks", ".keystore", "client.json", ".env")) for p in names)
output = root / "artifacts/android-release"
output.mkdir(parents=True, exist_ok=True)
package = output / f"edge-vpn-client-android-{version}.apk"
shutil.copy2(packages[0], package)
(output / "SHA256SUMS").write_text(hashlib.sha256(package.read_bytes()).hexdigest() + "  " + package.name + "\n")
(output / "ANDROID-VERIFICATION.txt").write_text(
    f"Source: {os.environ.get('GITHUB_SHA', '')}\nApplication: pub.hngs.vpn\nVersion: {version} ({code})\n"
    f"Certificate SHA256: {fingerprint}\nABIs: {', '.join(sorted(abis))}\n"
    "CI: Release build, certificate, package identity, minimum API and ABI checks passed.\n"
    "No emulator or physical-device runtime/connection validation performed.\n")
print(package.name, "verified release signature;", ", ".join(sorted(abis)))
