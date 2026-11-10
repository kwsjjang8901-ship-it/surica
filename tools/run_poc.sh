#!/usr/bin/env bash
# Suricata 연동 PoC 실행:
#   센서 설정 렌더 -> [AssetID: Zeek + 자산 판정] -> [Suricata 8: 설정 검사 -> 경보] -> 전송 스트림 -> 경보·자산 결합
#
# 사용법: tools/run_poc.sh [옵션] <pcap>
#   -c FILE    센서 설정 (기본: config/sensor.example.yaml)
#   -S on|off  Suricata on/off (설정 파일의 suricata.enabled를 이번 실행에서만 덮어씀)
#   -a DIR     AssetID 저장소(claudtest2) 경로. 지정하면 Zeek 자산 판정까지 실행 (환경 변수 ASSETID_ROOT)
#   -A FILE    이미 만든 assets.json 사용 (-a 대신)
#   -R FILE    ET 등 외부 룰 묶음(suricata.rules). 없으면 빈 룰 파일
#   -r FILE    추가 룰 파일 (local.rules 뒤에 붙임, 여러 번 가능)
#   -o DIR     출력 디렉터리 (기본: out/<pcap 이름>)
#   -h         도움말
#
# 환경 변수: SURICATA_IMAGE (기본 jasonish/suricata:8.0.6), PYTHON (기본 python3)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURICATA_IMAGE="${SURICATA_IMAGE:-jasonish/suricata:8.0.6}"
PYTHON="${PYTHON:-python3}"
CFG="$ROOT/config/sensor.example.yaml" SWITCH="" ASSETID_ROOT="${ASSETID_ROOT:-}" ASSETS="" ET_RULES="" OUT=""
EXTRA_RULES=()

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts "c:S:a:A:R:r:o:h" opt; do
	case "$opt" in
		c) CFG="$OPTARG" ;;
		S) SWITCH="$OPTARG" ;;
		a) ASSETID_ROOT="$OPTARG" ;;
		A) ASSETS="$OPTARG" ;;
		R) ET_RULES="$OPTARG" ;;
		r) EXTRA_RULES+=("$OPTARG") ;;
		o) OUT="$OPTARG" ;;
		h) usage 0 ;;
		*) usage 1 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage 1
case "$SWITCH" in ""|on|off) ;; *) echo "-S 는 on 또는 off" >&2; exit 1 ;; esac

PCAP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
[ -f "$PCAP" ] || { echo "pcap 없음: $1" >&2; exit 1; }
NAME="$(basename "$PCAP")"; NAME="${NAME%.*}"
OUT="${OUT:-$ROOT/out/$NAME}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# 이전 실행 결과 정리
rm -rf "$OUT/config" "$OUT/suricata" "$OUT/transport" "$OUT/rules"
rm -f "$OUT"/alerts.* "$OUT"/alerts_report.*

sw=(); [ -n "$SWITCH" ] && sw=(--suricata "$SWITCH")
cfg_get() { "$PYTHON" "$ROOT/tools/sensor_config.py" -c "$CFG" "${sw[@]}" --get "$1"; }
SURICATA="$(cfg_get suricata)"
NETS="$(cfg_get asset_nets)"
SENSOR_ID="$(cfg_get sensor_id)"

# ---------------------------------------------------------------- 1. 설정 렌더
echo "[1/4] 센서 설정 렌더: $CFG (Suricata $SURICATA)"
base=()
if [ "$SURICATA" = on ]; then
	command -v docker >/dev/null || { echo "Suricata 실행에는 docker가 필요합니다." >&2; exit 1; }
	mkdir -p "$OUT/config/suricata"
	# 배포본 suricata.yaml (이미지 버전의 기본 설정)을 꺼내 그 위에 센서 설정을 반영한다.
	docker run --rm --entrypoint cat "$SURICATA_IMAGE" /etc/suricata/suricata.yaml > "$OUT/config/suricata.base.yaml"
	base=(--base "$OUT/config/suricata.base.yaml")
	cp "$ROOT/suricata/threshold.config" "$OUT/config/suricata/threshold.config"
fi
"$PYTHON" "$ROOT/tools/render_config.py" -c "$CFG" -o "$OUT/config" "${sw[@]}" "${base[@]}" \
	--rule-path /rules --threshold-file /cfg/threshold.config | sed 's/^/      /'

# ---------------------------------------------------------------- 2. AssetID (Zeek + 자산 판정)
CONN_LOG=""
if [ -n "$ASSETID_ROOT" ]; then
	echo "[2/4] AssetID: $ASSETID_ROOT"
	mkdir -p "$OUT/assetid/zeek"
	cp "$OUT/config/zeek/nsm_sensor.zeek" "$OUT/assetid/zeek/nsm_sensor.zeek"
	# 상대 경로: AssetID run_poc.sh는 출력 zeek/ 디렉터리에서 zeek를 실행한다(Docker도 같음).
	"$ASSETID_ROOT/tools/run_poc.sh" -o "$OUT/assetid" -z nsm_sensor.zeek "$PCAP" > "$OUT/assetid.log" 2>&1 \
		|| { echo "AssetID 실행 실패: $OUT/assetid.log" >&2; exit 1; }
	ASSETS="$OUT/assetid/assets.json"
	CONN_LOG="$OUT/assetid/zeek/conn.log"
	echo "      자산 $("$PYTHON" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$ASSETS")개 -> $OUT/assetid/"
elif [ -n "$ASSETS" ]; then
	echo "[2/4] AssetID: 기존 자산 사용 $ASSETS"
else
	echo "[2/4] AssetID: 건너뜀 (-a 또는 -A 없음, 경보에는 IP 상태만 표시)"
fi

if [ "$SURICATA" = off ]; then
	echo "[3/4] Suricata: off -> 건너뜀"
	echo "[4/4] 경보 결합: 건너뜀"
	echo
	echo "결과: $OUT  (Suricata off: 생성물은 config/, assetid/ 뿐)"
	exit 0
fi

# ---------------------------------------------------------------- 3. Suricata
mkdir -p "$OUT/rules" "$OUT/suricata"
if [ -n "$ET_RULES" ]; then
	cp "$ET_RULES" "$OUT/rules/suricata.rules"
else
	echo "# 외부 룰 없음 (운영: suricata-update -c suricata/update/update.yaml)" > "$OUT/rules/suricata.rules"
fi
cp "$ROOT/suricata/rules/local.rules" "$OUT/rules/local.rules"
for r in "${EXTRA_RULES[@]}"; do cat "$r" >> "$OUT/rules/local.rules"; done

run_suricata() {
	docker run --rm --user "$(id -u):$(id -g)" \
		-v "$OUT/config/suricata:/cfg:ro" -v "$OUT/rules:/rules:ro" \
		-v "$(dirname "$PCAP"):/pcap:ro" -v "$OUT/suricata:/out" \
		--entrypoint suricata "$SURICATA_IMAGE" -c /cfg/suricata.yaml "$@"
}

echo "[3/4] Suricata ($SURICATA_IMAGE)"
# 설정 검사에 실패하면 Suricata만 끄고 나머지(AssetID)는 그대로 둔다 (장애 격리).
if ! run_suricata -T -l /out > "$OUT/suricata/config_test.log" 2>&1; then
	echo "      설정 검사 실패 -> Suricata 건너뜀 ($OUT/suricata/config_test.log)" >&2
	tail -5 "$OUT/suricata/config_test.log" | sed 's/^/      /' >&2
	echo
	echo "결과: $OUT  (Suricata 실패, AssetID 결과는 정상)"
	exit 3
fi
start=$(date +%s)
run_suricata -r "/pcap/$(basename "$PCAP")" -k none -l /out > "$OUT/suricata/run.log" 2>&1 \
	|| { echo "      Suricata 실행 실패: $OUT/suricata/run.log" >&2; exit 3; }
touch "$OUT/suricata/eve.json"
echo "      완료 ($(( $(date +%s) - start ))초), 룰 $(grep -c '^alert\|^drop\|^pass' "$OUT/rules/"*.rules | awk -F: '{s+=$2} END {print s}')개"

# ---------------------------------------------------------------- 4. 전송 스트림 + 경보 결합
echo "[4/4] 전송 스트림 · 경보 결합"
"$PYTHON" "$ROOT/tools/eve_envelope.py" "$OUT/suricata/eve.json" -t "$OUT/config/transport/streams.json" \
	-o "$OUT/transport" --sensor-id "$SENSOR_ID"
# 전송이 꺼져 있어도 센서 로컬 보기는 eve.json으로 만든다.
ALERTS="$OUT/transport/suricata_alert.jsonl"
[ -f "$ALERTS" ] || ALERTS="$OUT/suricata/eve.json"
join_args=("$ALERTS" -o "$OUT")
[ -n "$ASSETS" ] && join_args+=(-a "$ASSETS")
[ -n "$CONN_LOG" ] && join_args+=(-z "$CONN_LOG")
[ -n "$NETS" ] && join_args+=(-n "$NETS")
echo
"$PYTHON" "$ROOT/tools/alert_join.py" "${join_args[@]}"

echo "결과: $OUT"
echo "  - alerts_report.html  경보 + 자산 (브라우저)"
echo "  - alerts.csv          경보 목록 (Excel)"
echo "  - transport/          Manager로 보낼 스트림 (envelope JSONL)"
echo "  - config/             센서 설정에서 만든 Zeek·Suricata·전송 설정"
[ -n "$ASSETID_ROOT" ] && echo "  - assetid/            AssetID 결과 (report.html, assets.json)"
exit 0
