"""전송 envelope 변환과 경보·자산 결합 테스트."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import alert_join as aj  # noqa: E402
import eve_envelope as ee  # noqa: E402

T0 = 1793318400.0  # 2026-10-30 00:00:00 UTC


def ts_str(t):
    import datetime as dt
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def eve_alert(t, src, dst, sid=1, sig="TEST", cid="1:abc", **extra):
    ev = {"timestamp": ts_str(t), "flow_id": 11, "event_type": "alert", "src_ip": src, "src_port": 50000,
          "dest_ip": dst, "dest_port": 80, "proto": "TCP", "app_proto": "http", "community_id": cid,
          "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": sig,
                    "category": "c", "severity": 2, "metadata": {"mitre_technique_id": ["T1"]}}}
    ev.update(extra)
    return ev


def eve_stats(t, pkts):
    return {"timestamp": ts_str(t), "event_type": "stats",
            "stats": {"uptime": 1, "capture": {"kernel_drops": 0}, "decoder": {"pkts": pkts}, "tcp": {"x": 1}}}


TRANSPORT = {"streams": {"suricata_alert": True, "suricata_stats": True}, "stats_interval": 60,
             "alert_fields": {"app_layer": False, "payload": False, "rule_metadata": True}}


class TestEnvelope(unittest.TestCase):
    def test_parse_ts(self):
        for s in ("2026-10-30T09:00:00.000000+0900", "2026-10-30T09:00:00.000000+09:00",
                  "2026-10-30T00:00:00.000000Z", "2026-10-30T00:00:00.000000+0000"):
            self.assertEqual(ee.parse_ts(s).timestamp(), T0, s)

    def test_alert_allowlist(self):
        ev = eve_alert(T0, "10.0.0.1", "10.0.0.2", http={"url": "/secret?q=1"}, payload="AAAA",
                       flow={"pkts_toserver": 3}, extra_field="x")
        out = ee.convert([json.dumps(ev)], TRANSPORT, "s1")
        rec = out["suricata_alert"][0]
        self.assertEqual((rec["engine"], rec["stream"], rec["sensor_id"]), ("suricata", "suricata_alert", "s1"))
        self.assertEqual(rec["ts"], "2026-10-30T00:00:00.000000Z")
        self.assertEqual(rec["community_id"], "1:abc")
        d = rec["data"]
        for k in ("http", "payload", "flow", "extra_field"):
            self.assertNotIn(k, d)  # 기본: 앱 계층 값·페이로드·모르는 필드는 보내지 않음
        self.assertEqual(d["alert"]["metadata"], {"mitre_technique_id": ["T1"]})

        tr = dict(TRANSPORT, alert_fields={"app_layer": True, "payload": True, "rule_metadata": False})
        d = ee.convert([json.dumps(ev)], tr, "s1")["suricata_alert"][0]["data"]
        self.assertEqual(d["http"], {"url": "/secret?q=1"})
        self.assertEqual(d["payload"], "AAAA")
        self.assertNotIn("metadata", d["alert"])

    def test_stats_downsample(self):
        lines = [json.dumps(eve_stats(T0 + s, s)) for s in (0, 8, 16, 64, 72, 200)]
        st = ee.convert(lines, TRANSPORT, "s1")["suricata_stats"]
        # 0~59초 창 -> 마지막(16), 64~123초 창 -> 마지막(72), 200
        self.assertEqual([r["data"]["decoder"]["pkts"] for r in st], [16, 72, 200])
        self.assertNotIn("tcp", st[0]["data"])

    def test_disabled_stream_and_bad_lines(self):
        tr = dict(TRANSPORT, streams={"suricata_alert": False, "suricata_stats": True})
        out = ee.convert(["", "not json", '{"event_type":"alert"}', json.dumps(eve_alert(T0, "a", "b")),
                          json.dumps({"timestamp": ts_str(T0), "event_type": "http"})], tr, "s1")
        self.assertEqual(set(out), {"suricata_stats"})
        self.assertEqual(out["suricata_stats"], [])


ASSETS = [
    {"asset_id": "A-laptop", "display_name": "laptop-sales07", "hostname": "laptop-sales07", "id_type": "dhcp_client_id",
     "confidence": "높음", "roles": [], "os": "windows 10/11",
     "ips": [{"ip": "10.10.0.120", "first": T0 + 0, "last": T0 + 1000}]},
    {"asset_id": "A-phone", "display_name": "galaxy-s24", "hostname": "galaxy-s24", "id_type": "dhcp_client_id",
     "confidence": "높음", "roles": [], "os": "android 14",
     "ips": [{"ip": "10.10.0.120", "first": T0 + 5000, "last": T0 + 6000}]},
    {"asset_id": "A-dc", "display_name": "dc01", "hostname": "dc01", "id_type": "mac", "confidence": "중간",
     "roles": ["도메인 컨트롤러", "DNS 서버"], "os": "",
     "ips": [{"ip": "10.10.1.10", "first": T0, "last": T0 + 9000}]},
    {"asset_id": "A-web", "display_name": "srv-web01", "hostname": "", "id_type": "mac", "confidence": "중간",
     "roles": ["웹 서버"], "os": "linux(ubuntu)",
     "ips": [{"ip": "10.10.1.20", "first": T0, "last": T0 + 9000}]},
    {"asset_id": "A-relay", "display_name": "", "hostname": "", "id_type": "ip", "confidence": "낮음",
     "roles": [], "os": "", "multi_machine_accounts": ["corp\\pc01$", "corp\\pc02$"],
     "ips": [{"ip": "10.10.0.66", "first": T0, "last": T0 + 9000}]},
]


def norm(evs):
    """eve 경보 -> load_alerts 결과와 같은 형태."""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    for ev in evs:
        tmp.write(json.dumps(ev) + "\n")
    tmp.close()
    try:
        return aj.load_alerts(tmp.name)
    finally:
        os.unlink(tmp.name)


class TestJoin(unittest.TestCase):
    def setUp(self):
        self.index = aj.AssetIndex(ASSETS, ["10.0.0.0/8"], grace=300)

    def test_lookup_ip_reuse(self):
        L = self.index.lookup
        self.assertEqual(L("10.10.0.120", T0 + 500)[:2], (aj.STATUS_ASSET, ASSETS[0]))
        self.assertEqual(L("10.10.0.120", T0 + 5500)[:2], (aj.STATUS_ASSET, ASSETS[1]))
        # 구간 경계 grace 안
        self.assertEqual(L("10.10.0.120", T0 + 1200)[:2], (aj.STATUS_ASSET, ASSETS[0]))
        self.assertEqual(L("10.10.0.120", T0 + 4800)[:2], (aj.STATUS_ASSET, ASSETS[1]))
        # 두 구간 사이(어느 쪽에서도 grace 밖): 가까운 자산을 참고로
        st, a, dist = L("10.10.0.120", T0 + 2000)
        self.assertEqual((st, a["asset_id"], dist), (aj.STATUS_GAP, "A-laptop", 1000))
        st, a, _ = L("10.10.0.120", T0 + 4000)
        self.assertEqual((st, a["asset_id"]), (aj.STATUS_GAP, "A-phone"))
        # 첫 구간 이전
        self.assertEqual(L("10.10.0.120", T0 - 1000)[0], aj.STATUS_GAP)
        self.assertEqual(L("10.99.0.1", T0)[:2], (aj.STATUS_UNKNOWN, None))
        self.assertEqual(L("8.8.8.8", T0)[:2], (aj.STATUS_EXTERNAL, None))
        self.assertEqual(L("fd00::1", T0)[0], aj.STATUS_EXTERNAL)   # 대역 밖 IPv6
        self.assertEqual(L("not-an-ip", T0)[0], aj.STATUS_EXTERNAL)

    def test_join_group_and_flags(self):
        evs = [
            eve_alert(T0 + 100, "10.10.0.120", "10.10.1.10", sid=10, sig="ET EXPLOIT Kerberos", cid="1:k"),
            eve_alert(T0 + 101, "10.10.0.120", "10.10.1.10", sid=10, sig="ET EXPLOIT Kerberos", cid="1:k"),
            eve_alert(T0 + 102, "10.10.0.120", "10.10.1.10", sid=11, sig="ET OTHER", cid="1:k"),
            eve_alert(T0 + 5100, "10.10.0.120", "8.8.8.8", sid=12, sig="ET POLICY", cid="1:p"),
            eve_alert(T0 + 200, "10.10.0.66", "10.10.1.20", sid=13, sig="ET EXPLOIT Windows SMB RCE", cid="1:w"),
        ]
        groups = aj.join(norm(evs), self.index, {"1:k": "Czeek1"})
        by = {(g["community_id"], g["signature_id"]): g for g in groups}
        self.assertEqual(len(groups), 4)
        k = by[("1:k", 10)]
        self.assertEqual((k["count"], k["first"], k["last"]), (2, T0 + 100, T0 + 101))
        self.assertEqual(k["src"]["name"], "laptop-sales07")
        self.assertEqual(k["dest"]["asset_id"], "A-dc")
        self.assertEqual(k["zeek_uid"], "Czeek1")
        self.assertIn("중요 서버 대상: 도메인 컨트롤러", k["flags"])
        p = by[("1:p", 12)]
        self.assertEqual(p["src"]["name"], "galaxy-s24")       # 같은 IP, 다른 시각 -> 다른 자산
        self.assertEqual(p["dest"]["status"], aj.STATUS_EXTERNAL)
        self.assertNotIn("zeek_uid", p)
        w = by[("1:w", 13)]
        self.assertTrue(any("다중 머신 계정" in f and f.startswith("출발지") for f in w["flags"]))
        self.assertTrue(any("OS 불일치" in f for f in w["flags"]))

    def test_no_flow_key_collision(self):
        # community_id가 없으면 flow_id로 묶는다
        a = eve_alert(T0, "10.10.0.120", "8.8.8.8", cid="", flow_id=1)
        b = eve_alert(T0 + 1, "10.10.0.120", "8.8.8.8", cid="", flow_id=2)
        self.assertEqual(len(aj.join(norm([a, b]), self.index)), 2)

    def test_end_to_end_files(self):
        tmp = tempfile.mkdtemp()
        try:
            env = os.path.join(tmp, "suricata_alert.jsonl")
            out = ee.convert([json.dumps(eve_alert(T0 + 500, "10.10.0.120", "10.10.1.20", cid="1:x"))],
                             TRANSPORT, "s1")
            with open(env, "w") as f:
                for r in out["suricata_alert"]:
                    f.write(json.dumps(r) + "\n")
            assets = os.path.join(tmp, "assets.json")
            with open(assets, "w") as f:
                json.dump(ASSETS, f)
            conn = os.path.join(tmp, "conn.log")
            with open(conn, "w") as f:
                f.write('{"uid":"Cabc","community_id":"1:x"}\n')
            self.assertEqual(aj.main([env, "-a", assets, "-z", conn, "-o", tmp, "-n", "10.0.0.0/8"]), 0)
            with open(os.path.join(tmp, "alerts.json")) as f:
                res = json.load(f)
            self.assertEqual(res[0]["src"]["name"], "laptop-sales07")
            self.assertEqual(res[0]["dest"]["roles"], ["웹 서버"])
            self.assertEqual(res[0]["zeek_uid"], "Cabc")
            for name in ("alerts.csv", "alerts_report.txt", "alerts_report.html"):
                self.assertTrue(os.path.getsize(os.path.join(tmp, name)) > 0)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
