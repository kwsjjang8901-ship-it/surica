#!/usr/bin/env bash
# 통합 테스트 (Docker + Suricata 8 이미지 + AssetID 저장소 필요)
#   1. 생성 설정 충실도: 배포본 suricata.yaml과 생성본을 Suricata가 읽은 값(--dump-config)으로 비교해
#      의도한 키(출력, 룰, HOME_NET, AF_PACKET, 통계 주기, threshold) 외에는 바뀐 것이 없는지
#   2. Suricata on: demo.pcap 경보가 자산에 맞게 붙는지 (IP 재사용, 중요 서버, OS 불일치, Zeek uid)
#   3. Suricata on: extras.pcap AhnLab 통신 경보
#   4. Suricata off: Suricata 생성물이 없고, AssetID 결과가 AssetID 단독 실행과 같은지 (회귀)
#
# 사용법: ASSETID_ROOT=<claudtest2 경로> tests/e2e.sh

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ASSETID_ROOT:?ASSETID_ROOT(claudtest2 경로)를 지정하세요}"
ASSETID_ROOT="$(cd "$ASSETID_ROOT" && pwd)"
SURICATA_IMAGE="${SURICATA_IMAGE:-jasonish/suricata:8.0.6}"
PYTHON="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PCAPS="$ASSETID_ROOT/tests/pcaps"
fail=0
ok()  { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fail=1; }

echo "[1] 생성 설정 충실도 ($SURICATA_IMAGE)"
mkdir -p "$TMP/cfg"
docker run --rm --entrypoint cat "$SURICATA_IMAGE" /etc/suricata/suricata.yaml > "$TMP/cfg/base.yaml"
"$PYTHON" "$ROOT/tools/render_config.py" -c "$ROOT/config/sensor.example.yaml" --suricata on \
	-o "$TMP/r" --base "$TMP/cfg/base.yaml" --rule-path /rules --threshold-file /cfg/threshold.config >/dev/null
cp "$TMP/r/suricata/suricata.yaml" "$TMP/cfg/gen.yaml"
for f in base gen; do
	docker run --rm -v "$TMP/cfg:/c:ro" --entrypoint suricata "$SURICATA_IMAGE" -c "/c/$f.yaml" --dump-config 2>/dev/null \
		| sort > "$TMP/cfg/$f.dump"
done
unexpected="$(diff "$TMP/cfg/base.dump" "$TMP/cfg/gen.dump" | grep '^[<>]' | sed 's/^[<>] //' | cut -d' ' -f1 \
	| grep -vE '^(af-packet|outputs)(\.|$)|^(default-rule-path|rule-files(\..*)?|threshold-file|stats\.interval|stats\.enabled|vars\.address-groups\.HOME_NET)$' \
	| sort -u || true)"
if [ -z "$unexpected" ]; then ok "의도한 키 외 변경 없음"; else bad "의도하지 않은 변경: $unexpected"; fi

echo "[2] Suricata on: demo.pcap"
"$ROOT/tools/run_poc.sh" -S on -a "$ASSETID_ROOT" -r "$ROOT/tests/rules/test.rules" -o "$TMP/on" "$PCAPS/demo.pcap" > "$TMP/on.log" 2>&1 \
	|| { cat "$TMP/on.log"; bad "run_poc 실패"; }
"$PYTHON" - "$TMP/on/alerts.json" <<'EOF' || fail=1
import json, sys
g = json.load(open(sys.argv[1]))
def check(cond, msg):
    print("  %s %s" % ("ok   " if cond else "FAIL ", msg))
    return cond
res = []
by = lambda sid: [x for x in g if x["signature_id"] == sid]
res.append(check(sorted(x["src"]["name"] for x in by(9900004)) == ["galaxy-s24", "laptop-sales07"],
                 "IP 재사용: 10.10.0.120 경보가 시각에 따라 laptop-sales07 / galaxy-s24에 붙음"))
krb = by(9900003)
res.append(check(krb and all(x["dest"]["asset_id"] == "A-96823b3723" and any("도메인 컨트롤러" in f for f in x["flags"]) for x in krb),
                 "Kerberos 경보 목적지 = dc01, 중요 서버 표시"))
res.append(check(any("OS 불일치" in f for x in by(9900005) for f in x["flags"]), "Windows 룰 -> Linux 자산 OS 불일치 표시"))
res.append(check(all(x.get("zeek_uid") for x in g), "모든 경보에 Zeek uid 연결 (Community ID)"))
sys.exit(0 if all(res) else 1)
EOF
for f in transport/suricata_alert.jsonl transport/suricata_stats.jsonl alerts_report.html; do
	[ -s "$TMP/on/$f" ] && ok "$f 생성" || bad "$f 없음"
done
if grep -q '"community_id"' "$TMP/on/assetid/zeek/conn.log"; then ok "on: conn.log에 community_id"; else bad "on: conn.log에 community_id 없음"; fi

echo "[3] Suricata on: extras.pcap (AhnLab 통신)"
"$ROOT/tools/run_poc.sh" -S on -a "$ASSETID_ROOT" -r "$ROOT/tests/rules/test.rules" -o "$TMP/ex" "$PCAPS/extras.pcap" > "$TMP/ex.log" 2>&1 \
	|| { cat "$TMP/ex.log"; bad "run_poc 실패"; }
if "$PYTHON" -c 'import json,sys; g=json.load(open(sys.argv[1])); sys.exit(0 if any(x["signature_id"]==9900006 and x["src"]["status"]=="자산" for x in g) else 1)' "$TMP/ex/alerts.json"; then
	ok "AhnLab V3 통신 경보가 출발지 자산에 붙음"
else
	bad "AhnLab 경보 없음 또는 자산 미결합"
fi

echo "[4] Suricata off: 회귀"
"$ROOT/tools/run_poc.sh" -S off -a "$ASSETID_ROOT" -o "$TMP/off" "$PCAPS/demo.pcap" > "$TMP/off.log" 2>&1 \
	|| { cat "$TMP/off.log"; bad "run_poc 실패"; }
for d in suricata transport rules alerts.json; do
	[ ! -e "$TMP/off/$d" ] && ok "off: $d 없음" || bad "off: $d 가 생성됨"
done
if grep -q '"community_id"' "$TMP/off/assetid/zeek/conn.log"; then bad "off: conn.log에 community_id가 있음"; else ok "off: conn.log 형식 그대로"; fi
nets="$("$PYTHON" "$ROOT/tools/sensor_config.py" -c "$ROOT/config/sensor.example.yaml" --get asset_nets)"
"$ASSETID_ROOT/tools/run_poc.sh" -n "$nets" -o "$TMP/alone" "$PCAPS/demo.pcap" > "$TMP/alone.log" 2>&1
# Zeek 연결 uid는 실행마다 무작위라 빼고 비교한다.
strip_uid() { sed -E 's/"uid":"[^"]*",//' "$1"; }
if cmp -s "$TMP/off/assetid/assets.json" "$TMP/alone/assets.json" \
	&& cmp -s <(strip_uid "$TMP/off/assetid/zeek/asset_signal.log") <(strip_uid "$TMP/alone/zeek/asset_signal.log"); then
	ok "off: assets.json, asset_signal.log가 AssetID 단독 실행과 같음"
else
	bad "off: AssetID 단독 실행과 결과가 다름"
fi

echo
[ "$fail" -eq 0 ] && echo "통합 테스트 통과" || { echo "통합 테스트 실패"; exit 1; }
