# surica — NSM 센서 Suricata 연동 (on/off)

NSM 센서(Zeek 기반 **자산 식별 · 탐지 · 메타데이터 선별 전송**)에 **Suricata 8을 선택 구성요소로 붙이는** 저장소입니다.
Suricata는 시그니처 경보만 맡고, 경보의 IP를 자산 식별(AssetID) 결과로 바꿔 **"어느 자산이 무슨 경보를 냈는지"** 를 보여 줍니다.

- 설계: [docs/DESIGN.md](docs/DESIGN.md)
- 자산 식별(AssetID, Zeek 패키지·리졸버): [`claudtest2`](https://github.com/kwsjjang8901-ship-it/claudtest2) 저장소. 이 저장소는 그 산출물(`assets.json`, Zeek 로그)만 사용합니다.
- 대상 버전: **Suricata 8.0.6** (7.0은 2026-07 EOL), Zeek 8.x/9.x(AssetID 기준)

## 원칙

| 원칙 | 내용 |
|---|---|
| Zeek = 메타데이터, Suricata = 경보 | Suricata 프로토콜 로그(http/dns/tls/flow)는 기본 off. 같은 연결의 이중 기록을 막음 |
| on/off | 센서 설정 하나(`sensor.yaml`)로 제어. **off이면 Suricata 관련 생성물이 하나도 없고 AssetID 결과는 단독 실행과 같음** |
| 장애 격리 | 별도 프로세스·패킷 복사(AF_PACKET fanout 분리)·전송 스트림. 설정 검사 실패 시 Suricata만 건너뜀 |
| 결합 키 | 경보 ↔ 자산: `(IP, 시각)` → 자산 IP 점유 구간. 경보 ↔ Zeek 로그: Community ID |

## on/off 설정 (`config/sensor.example.yaml`)

```yaml
asset_nets: [10.0.0.0/8, 172.16.0.0/12]   # Zeek AssetID::asset_nets 와 Suricata HOME_NET 공통 원천
suricata:
  enabled: false        # ★ 엔진 전체 on/off (출시 기본값 off)
  outputs: {alert: true, stats: true, anomaly: false, protocol_logs: false}
  alert_fields: {app_layer: false, payload: false, rule_metadata: true}   # 개인정보: URL·페이로드 기본 제외
transport:
  streams: {asset_signal: true, zeek_notice: true, suricata_alert: true, suricata_stats: true}
```

실제 동작 = `suricata.enabled` AND 해당 출력 on AND `transport.streams.<스트림>` on.
예를 들어 룰 튜닝 기간에는 엔진은 켜고 `suricata_alert` 전송만 꺼서 경보를 센서에만 쌓을 수 있습니다.
모르는 키(오타), 잘못된 타입·대역, Zeek fanout과 같은 `cluster_id`는 설정 오류로 거부합니다.

## 빠른 시작

필요한 것: `python3`(3.8+), `PyYAML`(Suricata 설정 생성용), `docker`, AssetID 저장소(`claudtest2`) 체크아웃.

```bash
# Suricata on: AssetID 자산 판정 + Suricata 경보 + 결합 리포트
tools/run_poc.sh -S on -a ../claudtest2 -r tests/rules/test.rules ../claudtest2/tests/pcaps/demo.pcap

# Suricata off: AssetID만 (기존과 같은 결과)
tools/run_poc.sh -S off -a ../claudtest2 ../claudtest2/tests/pcaps/demo.pcap
```

| 옵션 | 설명 |
|---|---|
| `-c FILE` | 센서 설정 (기본 `config/sensor.example.yaml`) |
| `-S on\|off` | 설정 파일의 `suricata.enabled`를 이번 실행에서만 덮어씀 |
| `-a DIR` | AssetID 저장소 경로 → Zeek 자산 판정까지 실행 (`ASSETID_ROOT`) |
| `-A FILE` | 이미 만든 `assets.json` 사용 |
| `-R FILE` | ET 등 외부 룰 묶음(`suricata.rules`). 운영에서는 `suricata-update -c suricata/update/update.yaml` |
| `-r FILE` | 추가 룰 파일 (여러 번 가능) |
| `-o DIR` | 출력 디렉터리 (기본 `out/<pcap 이름>/`) |

환경 변수: `SURICATA_IMAGE`(기본 `jasonish/suricata:8.0.6`).

## 결과물 (`out/<이름>/`)

| 파일 | 내용 |
|---|---|
| `alerts_report.html` | 경보 + 자산(이름·역할·OS), 참고 표시(중요 서버 대상, OS 불일치, 다중 머신 계정 IP, 점유 구간 밖), Zeek uid |
| `alerts_report.txt`, `alerts.csv`, `alerts.json` | 같은 내용의 텍스트·Excel·원본 |
| `transport/*.jsonl` | Manager로 보낼 스트림 (`suricata_alert`, `suricata_stats`) — 공통 envelope |
| `config/` | 센서 설정에서 만든 `state.json`, Zeek 설정, `suricata.yaml`, 전송 스트림 설정 |
| `assetid/` | AssetID 결과 (`report.html`, `assets.json`, Zeek 로그) |
| `suricata/` | Suricata 원본 `eve.json`, 설정 검사·실행 로그 |

데모 결과 예시 (`alerts_report.txt` 일부, IP 재사용 IP 10.10.0.120의 경보가 시각에 따라 다른 단말에 붙음):

```
2026-10-30 09:12:00  sev 3  [9900004] NSM-TEST 10.10.0.120 발신  x1
    laptop-sales07 [windows 10/11] (10.10.0.120) -> 93.184.215.14 (외부)
2026-10-30 13:01:00  sev 3  [9900004] NSM-TEST 10.10.0.120 발신  x1
    galaxy-s24 [android 14] (10.10.0.120) -> 93.184.215.14 (외부)
2026-10-30 09:00:15  sev 3  [9900003] NSM-TEST Kerberos AS-REQ  x1
    win10-hr01 [windows 10/11] (10.10.0.101) -> dc01 (dns) [도메인 컨트롤러, DNS 서버] (10.10.1.10)
    ! 중요 서버 대상: 도메인 컨트롤러, 파일 서버(SMB)
```

## 도구

| 도구 | 하는 일 |
|---|---|
| `tools/sensor_config.py` | 설정 로드·검증, 실제 동작 계산 (`--get suricata\|asset_nets\|effective`) |
| `tools/render_config.py` | `sensor.yaml` → `zeek/nsm_sensor.zeek`, `suricata/suricata.yaml`(배포본을 읽어 필요한 키만 바꾼 전체 설정), `transport/streams.json` |
| `tools/eve_envelope.py` | `eve.json` → 전송 스트림. 필드 허용 목록, 꺼진 스트림 미생성, stats 축약 |
| `tools/alert_join.py` | 경보 + `assets.json` (+ Zeek `conn.log`) → 자산 컨텍스트 경보·리포트 |

## 테스트

```bash
tests/run_tests.sh                               # 단위 테스트 (18)
ASSETID_ROOT=../claudtest2 tests/run_tests.sh    # + Docker 통합 테스트
```

통합 테스트(`tests/e2e.sh`):
1. 생성한 `suricata.yaml`을 배포본과 `suricata --dump-config`로 비교 → 의도한 키 외 변경 없음
2. `demo.pcap`: IP 재사용 결합, DC 대상 표시, OS 불일치 표시, 모든 경보에 Zeek uid 연결
3. `extras.pcap`: AhnLab V3 통신 경보의 자산 결합
4. off 회귀: Suricata 생성물 없음, conn.log 형식 그대로, AssetID 결과가 단독 실행과 같음

## 단계

| 단계 | 상태 |
|---|---|
| 1. PoC (pcap, 설정 렌더, 전송 envelope, 경보·자산 결합) | 완료 |
| 2. 센서 통합 (systemd, AF_PACKET 실시간 공존, 수집 에이전트 스트림·우선순위, 상태 보고, 부하 측정) | 예정 |
| 3. 연계 고도화 (자산 역할 → Suricata 주소 그룹, 자산 기반 우선순위, notice·경보 사건 묶기) | 예정 |
