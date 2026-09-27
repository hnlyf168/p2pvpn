from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("traffic_import", ROOT / "tools/import-traffic-history.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TrafficImport(unittest.TestCase):
    def test_import_has_same_day_boundary_and_keeps_only_aggregates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vpn-site-access.log"
            events = [
                {"time": "2026-09-26T15:59:59Z", "uri": "/?ticket=private", "status": 200},
                {"time": "2026-09-26T16:00:00Z", "uri": "/downloads/edge-vpn-client-linux-arm-0.3.3.zip", "status": 200},
                {"time": "2026-09-26T16:00:01Z", "uri": "/downloads/edge-vpn-client-linux-arm-0.3.3.zip", "status": 206},
                {"time": "2026-09-26T16:00:02Z", "uri": "/install.sh", "status": 200},
                {"time": "2026-09-26T16:00:03Z", "uri": "/admin/traffic", "status": 200},
                {"time": "2026-09-27T16:00:00Z", "uri": "/", "status": 200},
            ]
            path.write_text("\n".join(json.dumps(dict(event, method="GET", ip="private address", ua="private user agent")) for event in events) + "\nnot json\n", encoding="utf-8")
            result, invalid = module.aggregate([path, path], datetime(2026, 9, 27, tzinfo=timezone.utc))
            self.assertEqual(invalid, 1)
            self.assertEqual(result["days"]["2026-09-26"]["pageViews"], 1)
            self.assertEqual(result["days"]["2026-09-27"]["scriptRequests"], 1)
            self.assertEqual(sum(result["days"]["2026-09-27"]["downloads"].values()), 1)
            self.assertNotIn("private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
