#!/usr/bin/env python3
"""Sign an unsigned Android release with the SDK tools and an explicit PKCS12 store."""
import os, subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sdk_root = Path(os.environ["ANDROID_HOME"]) / "build-tools"
versions = [p for p in sdk_root.iterdir() if all(s.isdigit() for s in p.name.split(".")) and (p / "apksigner").is_file()]
sdk = max(versions, key=lambda p: tuple(map(int, p.name.split("."))))
candidates = list((root / "src/Android/obj/Release").glob("**/android/bin/pub.hngs.vpn.apk"))
assert len(candidates) == 1, "Expected exactly one unsigned universal APK"
output = root / "artifacts/android-build"
output.mkdir(parents=True, exist_ok=True)
aligned = output / "pub.hngs.vpn-aligned.apk"
signed = output / "pub.hngs.vpn-Signed.apk"
subprocess.run([str(sdk / "zipalign"), "-P", "16", "-f", "4", str(candidates[0]), str(aligned)], check=True)
temp = Path(os.environ["RUNNER_TEMP"])
subprocess.run([str(sdk / "apksigner"), "sign", "--ks", str(temp / "android-release.p12"),
    "--ks-type", "PKCS12", "--ks-key-alias", os.environ["ANDROID_KEY_ALIAS"],
    "--ks-pass", "file:" + str(temp / "android-key-password"),
    "--key-pass", "file:" + str(temp / "android-key-password"),
    "--out", str(signed), str(aligned)], check=True)
subprocess.run([str(sdk / "zipalign"), "-c", "-P", "16", "4", str(signed)], check=True)
print("Signed APK:", signed.name)
