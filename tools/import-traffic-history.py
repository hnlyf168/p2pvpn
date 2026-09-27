#!/usr/bin/env python3
"""One-time, offline import of sanitized Nginx JSON logs into daily aggregates.

Run while the control service is stopped, before first enabling statistics.
An existing output is never overwritten. No raw visitor data is written.
"""
import argparse
from datetime import datetime, timedelta, timezone
import gzip
import json
from pathlib import Path
import re

OFFSET = timezone(timedelta(hours=8))
PAGES = {"/", "/index.html", "/login", "/register", "/recover", "/downloads", "/guide",
         "/features", "/network", "/scenarios", "/pricing", "/faq", "/auth.html",
         "/downloads.html", "/guide.html", "/features.html", "/network.html", "/scenarios.html", "/pricing.html", "/faq.html"}
SCRIPTS = {"/install.sh", "/install.ps1", "/install.cmd"}
PACKAGE = re.compile(r"/downloads/(edge-vpn-(?:client|control|punch|relay)-(?:win-x64|win-x86|linux-x64|linux-arm64|linux-arm)-[0-9]+\.[0-9]+\.[0-9]+\.zip)\Z")


def aggregate(paths, cutoff):
    earliest = cutoff
    first_day = cutoff.astimezone(OFFSET).date() - timedelta(days=399)
    days, invalid, seen = {}, 0, set()
    for path in paths:
        path = Path(path).resolve()
        if path in seen:
            continue
        seen.add(path)
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                    at = datetime.fromisoformat(event["time"].replace("Z", "+00:00"))
                    if at.tzinfo is None:
                        raise ValueError("Timestamp needs timezone")
                    if at >= cutoff or at.astimezone(OFFSET).date() < first_day:
                        continue
                    if event["method"] != "GET" or int(event["status"]) != 200:
                        continue  # Old log format has no Range; never inflate resumed downloads.
                    uri = event["uri"].split("?", 1)[0]
                    uri = uri.rstrip("/") or "/"
                    package = PACKAGE.fullmatch(uri)
                    kind = "pageViews" if uri.lower() in PAGES else "scriptRequests" if uri.lower() in SCRIPTS else None
                    if kind is None and package is None:
                        continue
                    day = days.setdefault(at.astimezone(OFFSET).date().isoformat(), {"pageViews": 0, "scriptRequests": 0, "downloads": {}})
                    if kind:
                        day[kind] += 1
                    else:
                        name = package.group(1)
                        day["downloads"][name] = day["downloads"].get(name, 0) + 1
                    earliest = min(earliest, at)
                except (KeyError, ValueError, TypeError, AttributeError):
                    invalid += 1
    return {"schemaVersion": 1, "startedAt": earliest.isoformat(), "historyImported": True,
            "lastSavedAt": cutoff.isoformat(), "days": dict(sorted(days.items()))}, invalid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Statistics already exist; refusing to overwrite")
    logs = sorted(args.log_directory.glob("vpn-site-access.log*"))
    if not logs:
        raise SystemExit("No vpn-site-access.log files found")
    data, invalid = aggregate(logs, datetime.now(timezone.utc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, separators=(",", ":"))
        stream.write("\n")
    args.output.chmod(0o600)
    print(json.dumps({"days": len(data["days"]), "pageViews": sum(d["pageViews"] for d in data["days"].values()),
                      "downloads": sum(sum(d["downloads"].values()) for d in data["days"].values()),
                      "scriptRequests": sum(d["scriptRequests"] for d in data["days"].values()), "invalidLines": invalid}))


if __name__ == "__main__":
    main()
