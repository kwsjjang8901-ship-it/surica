#!/usr/bin/env bash
# 단위 테스트 + (Docker와 ASSETID_ROOT가 있으면) 통합 테스트
#   tests/run_tests.sh
#   ASSETID_ROOT=../claudtest2 tests/run_tests.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "== 단위 테스트"
"$PYTHON" -m unittest discover -s "$ROOT/tests/unit"

echo
echo "== 통합 테스트"
if [ -z "${ASSETID_ROOT:-}" ]; then
	echo "건너뜀: ASSETID_ROOT(claudtest2 경로)가 없음"
elif ! docker info >/dev/null 2>&1; then
	echo "건너뜀: docker를 쓸 수 없음"
else
	"$ROOT/tests/e2e.sh"
fi
