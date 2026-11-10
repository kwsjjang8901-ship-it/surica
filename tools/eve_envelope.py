#!/usr/bin/env python3
"""Suricata eve.json -> 전송 스트림(JSONL) 변환.

수집 에이전트(shipper)가 Manager로 보내기 전에 하는 일을 PoC로 구현한다.
  - event_type으로 스트림을 나눈다: alert -> suricata_alert, stats -> suricata_stats
  - 꺼진 스트림은 만들지 않는다(transport/streams.json 기준)
  - 허용 목록(allowlist)에 있는 필드만 보낸다. 앱 계층 값·페이로드는 alert_fields에서 켠 경우에만
  - suricata_stats는 stats_interval(초)마다 1건으로 줄인다
  - 모든 레코드를 Zeek 스트림과 같은 바깥 형식(envelope)으로 감싼다

envelope: {sensor_id, engine, stream, ts(UTC ISO), community_id, data}
"""

import argparse
import datetime as dt
import json
import os
import sys

ALERT_KEYS = ("timestamp", "flow_id", "in_iface", "src_ip", "src_port", "dest_ip", "dest_port",
              "proto", "app_proto", "direction", "community_id", "tx_id")
ALERT_INNER_KEYS = ("action", "gid", "signature_id", "rev", "signature", "category", "severity")
PAYLOAD_KEYS = ("payload", "payload_printable", "packet", "packet_info")
# 경보에 붙는 앱 계층 메타데이터 (alert_fields.app_layer가 켜져 있을 때만)
APP_LAYER_KEYS = ("http", "dns", "tls", "smb", "ssh", "ftp", "smtp", "krb5", "ldap", "dcerpc",
                  "rdp", "nfs", "snmp", "sip", "mqtt", "quic", "files", "fileinfo", "email")
STATS_KEYS = ("uptime", "capture", "decoder", "flow", "detect", "app_layer")


def parse_ts(s):
    """Suricata 시각 '2026-11-10T09:12:03.123456+0000' -> UTC datetime."""
    if s.endswith("Z"):
        s = s[:-1] + "+0000"
    if len(s) > 6 and s[-3] == ":" and s[-6] in "+-":  # +09:00 형식
        s = s[:-3] + s[-2:]
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(dt.timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def alert_data(ev, fields):
    d = {k: ev[k] for k in ALERT_KEYS if k in ev}
    a = ev.get("alert", {})
    inner = {k: a[k] for k in ALERT_INNER_KEYS if k in a}
    if fields.get("rule_metadata") and "metadata" in a:
        inner["metadata"] = a["metadata"]
    d["alert"] = inner
    if fields.get("payload"):
        d.update({k: ev[k] for k in PAYLOAD_KEYS if k in ev})
    if fields.get("app_layer"):
        d.update({k: ev[k] for k in APP_LAYER_KEYS if k in ev})
    return d


def stats_data(ev):
    st = ev.get("stats", {})
    return {k: st[k] for k in STATS_KEYS if k in st}


def envelope(sensor_id, stream, t, data, community_id=None):
    e = {"sensor_id": sensor_id, "engine": "suricata", "stream": stream, "ts": iso(t)}
    if community_id:
        e["community_id"] = community_id
    e["data"] = data
    return e


def convert(lines, transport, sensor_id):
    """eve 줄들 -> {stream: [envelope, ...]}. 꺼진 스트림은 결과에 없다."""
    streams = transport["streams"]
    fields = transport.get("alert_fields", {})
    interval = float(transport.get("stats_interval", 60))
    out = {name: [] for name in ("suricata_alert", "suricata_stats") if streams.get(name)}
    last_stats = None
    bad = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            t = parse_ts(ev["timestamp"])
        except (ValueError, KeyError):
            bad += 1
            continue
        et = ev.get("event_type")
        if et == "alert" and "suricata_alert" in out:
            out["suricata_alert"].append(
                envelope(sensor_id, "suricata_alert", t, alert_data(ev, fields), ev.get("community_id")))
        elif et == "stats" and "suricata_stats" in out:
            # 마지막 통계는 항상 보내야 해서 일단 담아 두고, 간격 안의 이전 것을 바꿔 끼운다.
            rec = envelope(sensor_id, "suricata_stats", t, stats_data(ev))
            if last_stats is not None and (t - last_stats).total_seconds() < interval:
                out["suricata_stats"][-1] = rec
            else:
                out["suricata_stats"].append(rec)
                last_stats = t
    if bad:
        print("경고: 해석할 수 없는 eve 줄 %d개 무시" % bad, file=sys.stderr)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eve", help="Suricata eve.json")
    ap.add_argument("-t", "--transport", required=True, help="render_config.py가 만든 transport/streams.json")
    ap.add_argument("-o", "--out", required=True, help="출력 디렉터리 (<stream>.jsonl)")
    ap.add_argument("--sensor-id", default="sensor-01")
    a = ap.parse_args(argv)
    with open(a.transport, encoding="utf-8") as f:
        transport = json.load(f)
    with open(a.eve, encoding="utf-8") as f:
        out = convert(f, transport, a.sensor_id)
    os.makedirs(a.out, exist_ok=True)
    for name in ("suricata_alert", "suricata_stats"):
        path = os.path.join(a.out, name + ".jsonl")
        if name not in out:
            if os.path.exists(path):
                os.remove(path)
            continue
        with open(path, "w", encoding="utf-8") as f:
            for rec in out[name]:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print("  %-15s %d건 -> %s" % (name, len(out[name]), path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
