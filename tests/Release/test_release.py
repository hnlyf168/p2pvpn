import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release", ROOT / "tools/github-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "package.zip"
        self.manifest = json.loads((ROOT / "releases/manifests/0.3.4.json").read_text(encoding="utf-8"))

    def archive(self, name, data=b"example"):
        with zipfile.ZipFile(self.path, "w") as z:
            z.writestr(name, data)

    def test_real_manifest(self):
        release.validate_manifest(self.manifest, "0.3.4")

    def test_untrusted_download_and_unsafe_version(self):
        self.manifest["assets"][0]["url"] = "https://example.org/package.zip"
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            release.validate_manifest(self.manifest, "0.3.4")
        with self.assertRaises(ValueError):
            release.validate_version("../../credentials")

    def test_private_files_and_zip_traversal(self):
        for name in ("../outside", "/absolute", "C:/temp", "bin/client.json", "data/state.json", "admin-access.txt", "node.env", "secrets.json", "private.pem"):
            with self.subTest(name=name):
                self.archive(name)
                with self.assertRaises(ValueError):
                    release.verify_archive(self.path, {"runtime": "self-contained"})

    def test_runtime_library_is_not_a_secret_file(self):
        self.archive("bin/Microsoft.Extensions.Configuration.UserSecrets.dll")
        release.verify_archive(self.path, {"runtime": "self-contained"})

    def test_wrong_architecture_and_dynamic_elf(self):
        elf = bytearray(128)
        elf[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", elf, 18, 62)
        self.archive("P2PVpnClient", elf)
        with self.assertRaisesRegex(ValueError, "architecture"):
            release.verify_archive(self.path, {"runtime": "static-musl-nativeaot", "platform": "linux-arm64"})
        struct.pack_into("<Q", elf, 32, 64)
        struct.pack_into("<HH", elf, 54, 56, 1)
        struct.pack_into("<I", elf, 64, 3)  # PT_INTERP
        self.archive("P2PVpnClient", elf)
        with self.assertRaisesRegex(AssertionError, "fully static"):
            release.verify_archive(self.path, {"runtime": "static-musl-nativeaot", "platform": "linux-x64"})

    def test_json_output_uses_canonical_lf(self):
        release.write_json(self.path, {"example": "value"})
        self.assertNotIn(b"\r", self.path.read_bytes())

    def test_cache_hash_mismatch(self):
        asset = self.manifest["assets"][0]
        (self.path.parent / asset["name"]).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum"):
            release.acquire(asset, self.path, self.path.parent)

    def test_license_is_reproducible_and_preserves_program(self):
        self.archive("P2PVpnClient.exe", b"program")
        second = self.path.with_name("second.zip")
        second.write_bytes(self.path.read_bytes())
        release.add_windows_license(self.path)
        release.add_windows_license(second)
        self.assertEqual(release.sha256(self.path), release.sha256(second))
        self.assertIsNone(release.add_windows_license(self.path))
        with zipfile.ZipFile(self.path) as z:
            self.assertEqual(z.read("P2PVpnClient.exe"), b"program")
            self.assertIn("Wintun-LICENSE.txt", z.namelist())
            self.assertEqual(z.getinfo("Wintun-LICENSE.txt").create_system, 3)

    def test_modified_prepared_asset_is_rejected(self):
        root = self.path.parent
        (root / "release-manifest.json").write_text(json.dumps({"releaseVersion": "0.3.4", "repository": release.REPOSITORY, "sourceCommit": "a" * 40, "assets": []}), encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text("release", encoding="utf-8")
        (root / "SHA256SUMS").write_text("".join(f"{release.sha256(root / n)}  {n}\n" for n in ("release-manifest.json", "RELEASE_NOTES.md")), encoding="utf-8")
        release.load_verified_output(root)
        (root / "RELEASE_NOTES.md").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "checksum"):
            release.load_verified_output(root)


if __name__ == "__main__":
    unittest.main()
