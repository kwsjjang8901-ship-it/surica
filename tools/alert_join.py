#!/usr/bin/env python3
"""Suricata 경보 + AssetID 자산 -> 자산 컨텍스트가 붙은 경보 (PoC용 Manager 결합 대체).

입력
  경보:   eve_envelope.py가 만든 suricata_alert.jsonl, 또는 Suricata eve.json(alert만 사용)
  자산:   AssetID 리졸버(claudtest2 tools/asset_resolver.py)의 assets.json
          각 자산의 ips[] = IP 점유 구간 {ip, first, last}
  선택:   Zeek conn.log(JSON, community_id 포함) -> 경보에 Zeek uid 연결

결합 규칙
  경보의 src/dest IP마다, 그 IP의 점유 구간 중 경보 시각을 포함하는 구간(앞뒤 grace 허용)의 자산을 붙인다.
  DHCP로 IP가 재할당돼도 경보 시각 기준 구간을 고르므로 '그 시각의 단말'에 붙는다.
    자산          : 구간 안
    점유 구간 밖   : 같은 IP의 자산은 있으나 경보 시각이 어느 구간에도 들지 않음 (가장 가까운 자산을 참고로 표시)
    미식별 내부    : 자산 대역 IP지만 자산 없음
    외부          : 자산 대역 밖
  같은 연결(community_id, 없으면 flow_id)의 같은 룰 경보는 한 건으로 묶는다(count, first, last).

출력 (-o DIR): alerts.json, alerts.csv, alerts_report.txt, alerts_report.html
표준 라이브러리만 사용한다.
"""

import argparse
import bisect
import csv
import datetime as dt
import html
import ipaddress
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eve_envelope import parse_ts  # noqa: E402

DEFAULT_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]
CRITICAL_ROLES = {"도메인 컨트롤러", "DB 서버", "파일 서버(SMB)", "AhnLab MDS", "AhnLab EPP 서버"}
NON_WINDOWS_OS = ("linux", "macos", "android", "ios", "unix", "samba")
STATUS_ASSET, STATUS_GAP, STATUS_UNKNOWN, STATUS_EXTERNAL = "자산", "점유 구간 밖", "미식별 내부", "외부"


# ---------------------------------------------------------------- 입력

def load_alerts(path):
    """envelope JSONL 또는 eve.json -> 정규화된 경보 목록."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if "data" in rec and rec.get("stream") == "suricata_alert":
                ev = rec["data"]
            elif rec.get("event_type") == "alert":
                ev = rec
            else:
                continue
            a = ev.get("alert", {})
            try:
                ts = parse_ts(ev["timestamp"]).timestamp()
            except (KeyError, ValueError):
                continue
            out.append({
                "ts": ts,
                "community_id": ev.get("community_id", ""),
                "flow_id": ev.get("flow_id"),
                "proto": ev.get("proto", ""),
                "app_proto": ev.get("app_proto", ""),
                "src_ip": ev.get("src_ip", ""), "src_port": ev.get("src_port"),
                "dest_ip": ev.get("dest_ip", ""), "dest_port": ev.get("dest_port"),
                "signature_id": a.get("signature_id"), "rev": a.get("rev"),
                "signature": a.get("signature", ""), "category": a.get("category", ""),
                "severity": a.get("severity", 3), "action": a.get("action", ""),
                "metadata": a.get("metadata", {}),
            })
    out.sort(key=lambda x: x["ts"])
    return out


def load_conn_index(path):
    """Zeek conn.log(JSON) -> community_id -> uid."""
    idx = {}
    if not path or not os.path.exists(path):
        return idx
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("{"):
                continue
            try:
                c = json.loads(line)
            except ValueError:
                continue
            cid = c.get("community_id")
            if cid and cid not in idx:
                idx[cid] = c.get("uid", "")
    return idx


class AssetIndex:
    """IP -> 시작 시각 순 점유 구간 [(first, last, asset)]."""

    def __init__(self, assets, nets, grace):
        self.grace = grace
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets]
        self.by_ip = defaultdict(list)
        for a in assets:
            for t in a.get("ips", []):
                self.by_ip[t["ip"]].append((float(t["first"]), float(t["last"]), a))
        for v in self.by_ip.values():
            v.sort(key=lambda x: x[0])
        self.starts = {ip: [t[0] for t in v] for ip, v in self.by_ip.items()}

    def internal(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.nets)

    def lookup(self, ip, ts):
        """-> (상태, 자산 또는 None, 거리(초))."""
        tens = self.by_ip.get(ip)
        if not tens:
            return (STATUS_UNKNOWN if self.internal(ip) else STATUS_EXTERNAL), None, None
        # ts 직전에 시작한 구간과 그 다음 구간만 보면 된다(같은 IP의 구간은 겹치지 않음).
        i = bisect.bisect_right(self.starts[ip], ts)
        best = None
        for first, last, asset in tens[max(0, i - 1):i + 1]:
            dist = 0.0 if first <= ts <= last else min(abs(ts - first), abs(ts - last))
            if best is None or dist < best[0]:
                best = (dist, asset)
        dist, asset = best
        if dist <= self.grace:
            return STATUS_ASSET, asset, dist
        return STATUS_GAP, asset, dist


# ---------------------------------------------------------------- 결합

def side(index, ip, port, ts):
    status, asset, dist = index.lookup(ip, ts)
    s = {"ip": ip, "port": port, "status": status}
    if asset is not None:
        s.update({
            "asset_id": asset["asset_id"],
            "name": asset.get("display_name") or asset.get("hostname") or "",
            "id_type": asset.get("id_type", ""),
            "confidence": asset.get("confidence", ""),
            "roles": asset.get("roles", []),
            "os": asset.get("os", ""),
        })
        if status == STATUS_GAP:
            s["gap_seconds"] = round(dist)
        if asset.get("multi_machine_accounts"):
            s["multi_machine_accounts"] = asset["multi_machine_accounts"]
    return s


def context_flags(al, src, dst):
    """자산 정보로 본 참고 사항 (경보 심각도는 바꾸지 않는다)."""
    flags = []
    crit = sorted(CRITICAL_ROLES & set(dst.get("roles", [])))
    if crit:
        flags.append("중요 서버 대상: " + ", ".join(crit))
    for who, s in (("출발지", src), ("목적지", dst)):
        if s.get("multi_machine_accounts"):
            flags.append("%s가 다중 머신 계정 인증 IP (NTLM 릴레이 등 의심)" % who)
    sig = al["signature"].lower()
    os_ = dst.get("os", "").lower()
    if "windows" in sig and os_ and not os_.startswith("windows") and any(k in os_ for k in NON_WINDOWS_OS):
        flags.append("대상 OS 불일치 가능 (룰: Windows, 자산: %s)" % dst["os"])
    if src["status"] == STATUS_GAP or dst["status"] == STATUS_GAP:
        flags.append("점유 구간 밖 IP (자산 추정 불확실)")
    return flags


def join(alerts, index, conn_idx=None):
    conn_idx = conn_idx or {}
    groups = {}
    for al in alerts:
        flow_key = al["community_id"] or ("flow:%s" % al["flow_id"])
        key = (flow_key, al["signature_id"])
        g = groups.get(key)
        if g is not None:
            g["count"] += 1
            g["last"] = al["ts"]
            continue
        src = side(index, al["src_ip"], al["src_port"], al["ts"])
        dst = side(index, al["dest_ip"], al["dest_port"], al["ts"])
        g = {
            "first": al["ts"], "last": al["ts"], "count": 1,
            "signature_id": al["signature_id"], "rev": al["rev"], "signature": al["signature"],
            "category": al["category"], "severity": al["severity"], "action": al["action"],
            "proto": al["proto"], "app_proto": al["app_proto"],
            "community_id": al["community_id"], "src": src, "dest": dst,
            "flags": context_flags(al, src, dst),
        }
        if al["metadata"]:
            g["metadata"] = al["metadata"]
        if al["community_id"] in conn_idx:
            g["zeek_uid"] = conn_idx[al["community_id"]]
        groups[key] = g
    return sorted(groups.values(), key=lambda g: (g["severity"], g["first"]))


# ---------------------------------------------------------------- 출력

def fmt_ts(ts, tz):
    return dt.datetime.fromtimestamp(ts, dt.timezone(dt.timedelta(hours=tz))).strftime("%Y-%m-%d %H:%M:%S")


def side_text(s):
    if s["status"] == STATUS_ASSET:
        label = s["name"] or s["asset_id"]
        extra = [r for r in s.get("roles", [])[:2]] + ([s["os"]] if s.get("os") else [])
        return "%s%s (%s)" % (label, " [%s]" % ", ".join(extra) if extra else "", s["ip"])
    if s["status"] == STATUS_GAP:
        return "%s (%s, 가까운 자산 %s)" % (s["ip"], s["status"], s["name"] or s["asset_id"])
    return "%s (%s)" % (s["ip"], s["status"])


def write_json(path, groups):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(groups, f, ensure_ascii=False, indent=1)


CSV_FIELDS = ["first", "last", "count", "severity", "signature_id", "signature", "category",
              "src_ip", "src_port", "src_status", "src_asset_id", "src_name", "src_roles", "src_os",
              "dest_ip", "dest_port", "dest_status", "dest_asset_id", "dest_name", "dest_roles", "dest_os",
              "proto", "app_proto", "community_id", "zeek_uid", "flags"]


def write_csv(path, groups, tz):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for g in groups:
            row = {"first": fmt_ts(g["first"], tz), "last": fmt_ts(g["last"], tz), "count": g["count"],
                   "severity": g["severity"], "signature_id": g["signature_id"], "signature": g["signature"],
                   "category": g["category"], "proto": g["proto"], "app_proto": g["app_proto"],
                   "community_id": g["community_id"], "zeek_uid": g.get("zeek_uid", ""),
                   "flags": " | ".join(g["flags"])}
            for p, s in (("src", g["src"]), ("dest", g["dest"])):
                row.update({p + "_ip": s["ip"], p + "_port": s["port"], p + "_status": s["status"],
                            p + "_asset_id": s.get("asset_id", ""), p + "_name": s.get("name", ""),
                            p + "_roles": ", ".join(s.get("roles", [])), p + "_os": s.get("os", "")})
            w.writerow(row)


def summary(groups):
    st = Counter()
    targets = Counter()
    for g in groups:
        for s in (g["src"], g["dest"]):
            st[s["status"]] += 1
        d = g["dest"]
        if d["status"] == STATUS_ASSET:
            targets[(d["asset_id"], d["name"] or d["asset_id"])] += g["count"]
    return st, targets


def write_report(path, groups, tz, n_raw):
    st, targets = summary(groups)
    lines = []
    p = lines.append
    p("Suricata 경보 + 자산 컨텍스트")
    p("=" * 60)
    p("경보 %d건 -> 연결·룰 기준 %d건으로 묶음" % (n_raw, len(groups)))
    ends = sum(st.values())
    if ends:
        p("경보 양끝 IP의 자산 결합: " + ", ".join("%s %d" % (k, st[k]) for k in
                                         (STATUS_ASSET, STATUS_GAP, STATUS_UNKNOWN, STATUS_EXTERNAL) if st[k]))
    if targets:
        p("")
        p("[경보 대상 자산 상위]")
        for (aid, name), n in targets.most_common(10):
            p("  %-12s %-24s %d건" % (aid, name, n))
    p("")
    p("[경보 목록] (심각도 순)")
    for g in groups:
        p("%s  sev %s  [%s] %s  x%d" % (fmt_ts(g["first"], tz), g["severity"], g["signature_id"], g["signature"], g["count"]))
        p("    %s -> %s" % (side_text(g["src"]), side_text(g["dest"])))
        for fl in g["flags"]:
            p("    ! " + fl)
        if g.get("zeek_uid"):
            p("    Zeek uid: %s" % g["zeek_uid"])
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


HTML_HEAD = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Suricata 경보 자산 결합</title>
<style>
:root{--bg:#fff;--fg:#1d2330;--muted:#5f6b7a;--line:#dde2ea;--chip:#eef2f7;--warn:#a34b00;--s1:#b42318;--s2:#b54708;--s3:#475467}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ee;--muted:#9aa4b2;--line:#2c323b;--chip:#222831;--warn:#f5a25d;--s1:#f97066;--s2:#fdb022;--s3:#98a2b3}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:0 0 4px}.muted{color:var(--muted)}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.card{border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:120px}
.card b{display:block;font-size:20px}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:860px;font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--bg);white-space:nowrap}
.sev{font-weight:700}.sev1{color:var(--s1)}.sev2{color:var(--s2)}.sev3{color:var(--s3)}
.chip{display:inline-block;background:var(--chip);border-radius:4px;padding:0 4px;margin:1px 2px 1px 0;font-size:12px}
.flag{color:var(--warn);font-size:12px}
input{box-sizing:border-box;width:100%;max-width:360px;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
</style></head><body><main>
"""


def side_html(s):
    e = html.escape
    if s["status"] in (STATUS_ASSET, STATUS_GAP):
        name = e(s.get("name") or s.get("asset_id", ""))
        chips = "".join('<span class="chip">%s</span>' % e(r) for r in s.get("roles", []))
        os_ = ' <span class="muted">%s</span>' % e(s["os"]) if s.get("os") else ""
        gap = ' <span class="flag">(%s)</span>' % e(s["status"]) if s["status"] == STATUS_GAP else ""
        return "<b>%s</b>%s%s<br>%s:%s <span class='muted'>%s</span><br>%s" % (
            name, gap, os_, e(s["ip"]), e(str(s["port"] or "")), e(s.get("asset_id", "")), chips)
    return "%s:%s<br><span class='muted'>%s</span>" % (e(s["ip"]), e(str(s["port"] or "")), e(s["status"]))


def write_html(path, groups, tz, n_raw):
    e = html.escape
    st, targets = summary(groups)
    out = [HTML_HEAD, "<h1>Suricata 경보 + 자산 컨텍스트</h1>",
           "<div class='muted'>경보 %d건 · 연결·룰 기준 %d건</div><div class='cards'>" % (n_raw, len(groups))]
    for k in (STATUS_ASSET, STATUS_GAP, STATUS_UNKNOWN, STATUS_EXTERNAL):
        out.append("<div class='card'><span class='muted'>IP 결합: %s</span><b>%d</b></div>" % (e(k), st[k]))
    out.append("</div><p><input id='q' placeholder='검색 (룰, 자산, IP)' oninput='f()'></p><div class='wrap'><table id='t'>"
               "<thead><tr><th>시각</th><th>심각도</th><th>룰</th><th>출발지</th><th>목적지</th><th>참고</th></tr></thead><tbody>")
    for g in groups:
        flags = "".join("<div class='flag'>%s</div>" % e(x) for x in g["flags"])
        if g.get("zeek_uid"):
            flags += "<div class='muted'>Zeek uid %s</div>" % e(g["zeek_uid"])
        out.append("<tr><td>%s<br><span class='muted'>x%d</span></td><td class='sev sev%s'>%s</td>"
                   "<td>%s<br><span class='muted'>%s · sid %s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                       e(fmt_ts(g["first"], tz)), g["count"], e(str(min(int(g["severity"] or 3), 3))),
                       e(str(g["severity"])), e(g["signature"]), e(g["category"]), e(str(g["signature_id"])),
                       side_html(g["src"]), side_html(g["dest"]), flags))
    out.append("</tbody></table></div><script>function f(){var q=document.getElementById('q').value.toLowerCase();"
               "document.querySelectorAll('#t tbody tr').forEach(function(r){r.style.display="
               "r.textContent.toLowerCase().indexOf(q)<0?'none':''})}</script></main></body></html>\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(out))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("alerts", help="suricata_alert.jsonl 또는 eve.json")
    ap.add_argument("-a", "--assets", help="AssetID assets.json (없으면 IP 상태만 표시)")
    ap.add_argument("-z", "--conn-log", help="Zeek conn.log (JSON, community_id 포함)")
    ap.add_argument("-o", "--out", required=True, help="출력 디렉터리")
    ap.add_argument("-n", "--nets", help="자산 대역, 쉼표 구분 (기본: 사설 대역)")
    ap.add_argument("--grace", type=float, default=300, help="점유 구간 앞뒤 허용 시간(초, 기본 300)")
    ap.add_argument("--tz", type=float, default=9, help="표시 시간대 (UTC 기준 시간, 기본 9)")
    a = ap.parse_args(argv)

    alerts = load_alerts(a.alerts)
    assets = []
    if a.assets:
        with open(a.assets, encoding="utf-8") as f:
            assets = json.load(f)
    nets = [n.strip() for n in a.nets.split(",") if n.strip()] if a.nets else DEFAULT_NETS
    index = AssetIndex(assets, nets, a.grace)
    groups = join(alerts, index, load_conn_index(a.conn_log))

    os.makedirs(a.out, exist_ok=True)
    write_json(os.path.join(a.out, "alerts.json"), groups)
    write_csv(os.path.join(a.out, "alerts.csv"), groups, a.tz)
    write_html(os.path.join(a.out, "alerts_report.html"), groups, a.tz, len(alerts))
    text = write_report(os.path.join(a.out, "alerts_report.txt"), groups, a.tz, len(alerts))
    print(text if len(text) < 6000 else text[:6000] + "\n... (alerts_report.txt 참고)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
