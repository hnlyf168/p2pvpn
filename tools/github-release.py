#!/usr/bin/env python3
"""Publish verified, prebuilt packages. This tool does not compile binaries."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "hnlyf168/p2pvpn"
MAX_PACKAGE = 512 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate_version(version):
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", version), "Invalid version")
    return version


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(newurl)
        require(new.scheme == "https" and old.netloc == new.netloc, "Cross-host/insecure redirect refused")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


HTTP = urllib.request.build_opener(RestrictedRedirect)


def validate_manifest(manifest, version):
    require(manifest["releaseVersion"] == validate_version(version), "Manifest version mismatch")
    require(manifest["assets"], "Empty manifest")
    names = set()
    for asset in manifest["assets"]:
        name = asset["name"]
        require(re.fullmatch(r"edge-vpn-[a-z0-9.-]+\.zip", name), "Unsafe package name")
        require(name not in names, "Duplicate package")
        names.add(name)
        require(asset["kind"] in ("client", "control", "punch", "relay"), "Unknown component")
        require(asset["platform"] in ("linux-x64", "linux-arm64", "linux-arm", "win-x64"), "Unsupported platform")
        validate_version(asset["version"])
        require(name == f'edge-vpn-{asset["kind"]}-{asset["platform"]}-{asset["version"]}.zip', "Package metadata mismatch")
        require(asset["url"] == "https://vpn.hngs.pub/downloads/" + name, "Unapproved download URL")
        require(re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]), "Invalid SHA-256")
        require(isinstance(asset["size"], int) and 0 < asset["size"] <= MAX_PACKAGE, "Invalid size")
        expected = "static-musl-nativeaot" if asset["kind"] == "client" and asset["platform"].startswith("linux-") else "self-contained"
        require(asset["runtime"] == expected, "Unexpected runtime declaration")


def verify_archive(path, asset):
    with zipfile.ZipFile(path) as archive:
        names = set()
        total = 0
        for member in archive.infolist():
            name = member.filename
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and "\\" not in name and ":" not in name
                    and ".." not in parts, "Unsafe archive path")
            require(name not in names, "Duplicate archive entry")
            names.add(name)
            require((member.external_attr >> 16) & 0o170000 != 0o120000, "Archive symlink refused")
            lower = name.lower()
            basename = parts[-1].lower()
            require(basename not in ("client.json", "state.json", ".env", "claim.txt")
                    and not basename.endswith((".env", ".pem", ".key", ".pfx", ".p12"))
                    and "admin-access" not in lower
                    and not ("secrets" in basename and basename.endswith((".json", ".txt", ".yaml", ".yml", ".toml", ".xml")))
                    and not any(p.lower() in (".git", "data", "deployment") for p in parts),
                    "Private configuration found in archive: " + name)
            total += member.file_size
            require(total <= 2 * 1024**3, "Archive expands beyond limit")
        require(archive.testzip() is None, "ZIP CRC verification failed")
        if asset["runtime"] == "static-musl-nativeaot":
            require("P2PVpnClient" in names, "Missing native client")
            spec = importlib.util.spec_from_file_location("native_elf", ROOT / "tools/verify-native-elf.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            report = module.inspect_elf(archive.read("P2PVpnClient"))
            expected = {"linux-x64": (64, 62), "linux-arm64": (64, 183), "linux-arm": (32, 40)}[asset["platform"]]
            require((report["bits"], report["machine"]) == expected, "ELF architecture mismatch")
            return report
    return None


def acquire(asset, target, cache):
    cached = cache / asset["name"] if cache else None
    if cached and cached.is_file():
        require(cached.stat().st_size == asset["size"] and sha256(cached) == asset["sha256"], "Cached package checksum mismatch")
        shutil.copyfile(cached, target)
    else:
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "P2PVpn-Release"})
        with HTTP.open(request, timeout=180) as response, target.open("wb") as stream:
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                require(count <= asset["size"], "Download exceeds declared size")
                stream.write(chunk)
    require(target.stat().st_size == asset["size"] and sha256(target) == asset["sha256"], "Downloaded package checksum mismatch")


def add_windows_license(path):
    # Append with a fixed timestamp for reproducible output; executable bytes stay intact.
    with zipfile.ZipFile(path, "a", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        if "Wintun-LICENSE.txt" not in archive.namelist():
            entry = zipfile.ZipInfo("Wintun-LICENSE.txt", (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, (ROOT / "docs/third-party/Wintun-LICENSE.txt").read_bytes())
            return "Added Wintun-LICENSE.txt; executable files unchanged."
    return None


def prepare(args):
    version = validate_version(args.version)
    manifest_path = ROOT / "releases/manifests" / (version + ".json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest(manifest, version)
    require(not git("status", "--porcelain", "--untracked-files=normal"), "Commit all source and release inputs before preparing")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    require(not any(output.iterdir()), "Output directory must be empty")
    commit = git("rev-parse", "HEAD")
    inventory = {"releaseVersion": version, "repository": REPOSITORY, "sourceCommit": commit,
                 "sourceNote": manifest["sourceNote"], "assets": []}
    for asset in manifest["assets"]:
        path = output / asset["name"]
        acquire(asset, path, args.cache)
        elf = verify_archive(path, asset)
        adjustment = add_windows_license(path) if asset["platform"] == "win-x64" else None
        record = dict(asset, sourceSha256=asset["sha256"], sha256=sha256(path), size=path.stat().st_size)
        if elf:
            record["elf"] = elf
        if adjustment:
            record["packagingAdjustment"] = adjustment
        inventory["assets"].append(record)
        print("Verified", asset["name"], flush=True)
    source = output / f"p2pvpn-source-{version}.zip"
    subprocess.run(["git", "archive", "--format=zip", "--prefix=p2pvpn-" + version + "/", "-o", str(source), commit], cwd=ROOT, check=True)
    inventory["assets"].append({"name": source.name, "kind": "source", "sha256": sha256(source), "size": source.stat().st_size})
    write_json(output / "release-manifest.json", inventory)
    rows = ["| 组件 | 平台 | 实际版本 | 运行方式 |", "| --- | --- | --- | --- |"]
    rows += [f'| {a["kind"]} | {a["platform"]} | {a["version"]} | {a["runtime"]} |' for a in manifest["assets"]]
    notes = f'''{manifest["title"]}

{manifest["sourceNote"]}

''' + "\n".join(rows) + f'''

Linux 客户端为静态 musl NativeAOT，已检查 ELF 架构、无 PT_INTERP、无 DT_NEEDED。ARM 32 位包适用于 ARMv7；不包含 Linux x86 32 位、ARMv6、Android 或其他未列出的平台。Windows 客户端和服务端包为自包含 .NET 发布，不标为 NativeAOT。

Windows 发布副本补充 Wintun 许可证，程序文件未改动，最终校验值以本 Release 的 SHA256SUMS 为准；原始下载包校验值记录在 release-manifest.json 的 sourceSha256。

安装客户端：访问 https://vpn.hngs.pub 注册并验证邮箱，创建网络、添加设备后复制平台生成的一键安装命令。命令包含个人安装票据，请勿分享。离线安装及服务器部署说明见 [README](https://github.com/{REPOSITORY}/blob/v{version}/README.md)。主控制服务只做认证和打洞协调，中继节点单独部署。

附带源码 ZIP、组件清单及 SHA-256 校验文件。源码提交：`{commit}`。GitHub 自动提供的 Source code 也对应同一标签。

这次发布使用已编译成品，流水线负责校验和发布；没有在 GitHub 上重新编译所有平台，也不表示所有组件版本相同。
'''
    (output / "RELEASE_NOTES.md").write_text(notes, encoding="utf-8")
    checksums = "".join(f"{sha256(p)}  {p.name}\n" for p in sorted(output.iterdir()) if p.is_file())
    (output / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    print("Prepared", output)


class GitHub:
    def __init__(self, token):
        self.token = token

    def request(self, path, method="GET", payload=None, file=None):
        url = path if path.startswith("https://") else "https://api.github.com/repos/" + REPOSITORY + path
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname in ("api.github.com", "uploads.github.com")
                and parsed.path.startswith("/repos/" + REPOSITORY + "/"), "Unapproved GitHub endpoint")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "P2PVpn-Release"}
        if file:
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(file.stat().st_size)})
            with file.open("rb") as stream:
                request = urllib.request.Request(url, data=stream, headers=headers, method=method)
                with HTTP.open(request, timeout=600) as response:
                    return json.load(response)
        data = json.dumps(payload).encode() if payload is not None else None
        if data:
            headers["Content-Type"] = "application/json"
        with HTTP.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=90) as response:
            return json.load(response)

    def optional(self, path):
        try:
            return self.request(path)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise


def load_verified_output(output):
    inventory = json.loads((output / "release-manifest.json").read_text(encoding="utf-8"))
    validate_version(inventory["releaseVersion"])
    require(inventory["repository"] == REPOSITORY, "Repository mismatch")
    require(re.fullmatch(r"[a-f0-9]{40}", inventory["sourceCommit"]), "Invalid source commit")
    listed = {}
    for line in (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in listed, "Invalid checksum entry")
        path = output / name
        require(path.is_file() and not path.is_symlink() and sha256(path) == digest, "Prepared asset checksum mismatch")
        listed[name] = digest
    expected = {a["name"] for a in inventory["assets"]} | {"release-manifest.json", "RELEASE_NOTES.md"}
    require(set(listed) == expected, "Incomplete checksum inventory")
    require({p.name for p in output.iterdir()} == expected | {"SHA256SUMS"}, "Unexpected release file")
    for asset in inventory["assets"]:
        require(listed[asset["name"]] == asset["sha256"] and (output / asset["name"]).stat().st_size == asset["size"], "Inventory mismatch")
    return inventory


def publish(args):
    output = args.output.resolve()
    inventory = load_verified_output(output)
    require(inventory["sourceCommit"] == git("rev-parse", "HEAD"), "Prepared source differs from checkout")
    token = os.environ.get("GITHUB_TOKEN")
    if not token and args.git_credential:
        result = subprocess.run(["git", "credential-manager", "get"], input="protocol=https\nhost=github.com\nusername=hnlyf168\n\n", capture_output=True, text=True, check=True)
        token = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line).get("password")
    require(token, "Set GITHUB_TOKEN or explicitly use --git-credential")
    api = GitHub(token)
    version, commit = inventory["releaseVersion"], inventory["sourceCommit"]
    tag = "v" + version
    ref = api.optional("/git/ref/tags/" + tag)
    if ref:
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = api.request("/git/tags/" + obj["sha"])["object"]
        require(obj["type"] == "commit" and obj["sha"] == commit, "Existing tag points at different source; refusing to move it")
    release = None
    page = 1
    while True:
        batch = api.request(f"/releases?per_page=100&page={page}")
        matches = [r for r in batch if r["tag_name"] == tag]
        if matches:
            release = matches[0]
            break
        if len(batch) < 100:
            break
        page += 1
    notes = (output / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    if release is None:
        release = api.request("/releases", "POST", {"tag_name": tag, "target_commitish": commit,
            "name": notes.splitlines()[0], "body": notes, "draft": True, "prerelease": "-" in version})
    require(ref is not None or release["target_commitish"] == commit, "Existing draft source differs")
    assets = api.request(f'/releases/{release["id"]}/assets?per_page=100')
    existing = {a["name"]: a for a in assets}
    files = sorted(output.iterdir())
    require(set(existing) <= {p.name for p in files}, "Release contains unexpected assets")
    for path in files:
        uploaded = existing.get(path.name)
        if uploaded is None:
            require(release["draft"], "Published release is incomplete; refusing to modify it")
            endpoint = release["upload_url"].split("{")[0] + "?" + urllib.parse.urlencode({"name": path.name})
            uploaded = api.request(endpoint, "POST", file=path)
        require(uploaded.get("state") == "uploaded" and uploaded["size"] == path.stat().st_size
                and uploaded.get("digest") == "sha256:" + sha256(path), "Remote asset hash mismatch; draft retained: " + path.name)
        print("Uploaded and verified", path.name, flush=True)
    if release["draft"]:
        release = api.request(f'/releases/{release["id"]}', "PATCH", {"draft": False, "body": notes, "make_latest": "true" if "-" not in version else "false"})
    print(release["html_url"], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--version", required=True)
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--cache", type=Path)
    pub = sub.add_parser("publish")
    pub.add_argument("--output", type=Path, required=True)
    pub.add_argument("--git-credential", action="store_true")
    args = parser.parse_args()
    (prepare if args.command == "prepare" else publish)(args)


if __name__ == "__main__":
    main()
