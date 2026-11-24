# Suricata 연동 구조 설계 (on/off 가능한 시그니처 탐지 엔진 추가)

문서 버전: 0.3 (2026-11-24) · 대상: Suricata **8.0.6** · 자산 식별(AssetID): 센서 패키지는 nsm 저장소 `nsm_rules/asset-id/`, PoC·리졸버는 `claudtest2` 저장소([SPEC.md](https://github.com/kwsjjang8901-ship-it/claudtest2/blob/main/docs/SPEC.md)) · 경보를 NSM 탐지 흐름에 합치는 방법: nsm [SURICATA_INTEGRATION_DESIGN.md](https://github.com/kwsjjang8901-ship-it/nsm/blob/main/docs/SURICATA_INTEGRATION_DESIGN.md)

> 이 문서는 현재 NSM 센서 구성(Zeek 기반 **자산 식별 · 탐지(nsm_rules) · 메타데이터 선별 전송**)에
> Suricata를 **선택 구성요소**로 붙이는 구조를 정의한다. 탐지 스크립트(nsm_rules)와 수집 에이전트 코드는
> 이 저장소에 없으므로, 문서에 기록된 구조(선별 전송 → Manager(ClickHouse), mTLS·spool)를 전제로 한다.
>
> 0.3에서 바뀐 점(2026-11-24, nsm 설계 방식 B 결정): 경보는 Zeek를 거치지 않고 `suricata_alert` 스트림으로 **Manager에 바로**
> 가고(기본 켬), Manager가 단계·위험도·예외·사건 묶기·통합 상관을 한다. 센서 쪽은 eve 출력을 **경보·통계 파일로 나누고**(4장),
> **Community ID seed를 한 설정값**으로 Suricata·Zeek에 맞추며(3.1, 5.2), **룰 범위·경보 억제 기본값**을 정했다(4.1).
> 자산 식별 센서 패키지는 nsm `nsm_rules/asset-id/`로 옮겨졌다(2026-11-12). 이 저장소의 PoC는 여전히 `claudtest2`의 실행 도구·리졸버를 쓴다.
>
> 0.1(설계안)에서 바뀐 점: Suricata 설정을 include 파일이 아니라 **배포본을 읽어 만든 전체 설정**으로 바꿈(4장),
> 버전을 8.0.6으로 확정(12장), 1단계(PoC) 구현 반영(9~11장).

---

## 1. 목표와 원칙

| 목표 | 내용 |
|---|---|
| 시그니처 탐지 보강 | Zeek(행위·메타데이터 기반)에 없는 **알려진 공격 시그니처 탐지**(ET Open/사내 룰)를 추가 |
| 자산 컨텍스트 결합 | Suricata 경보의 IP를 AssetID 자산(호스트명·역할·OS)으로 바꿔 표시 — 원페이저 "IP 대신 호스트·역할로 탐지 표시" |
| on/off | 센서 단위로 켜고 끌 수 있고, **꺼져 있을 때 기존 동작·출력이 지금과 완전히 같음** |

설계 원칙

1. **Zeek가 메타데이터의 단일 원천, Suricata는 경보(alert) 전용.** Suricata의 프로토콜 로그(http/dns/tls/flow)는 기본 off.
   같은 연결을 두 엔진이 이중 기록하면 전송량만 늘고 Manager에서 중복 제거가 필요해진다.
2. **자산 판정은 지금처럼 Manager 한 곳.** 센서의 두 엔진은 판정하지 않고 사실(신호·경보)만 보낸다. Suricata 경보와 자산의 결합도 Manager에서 `(ip, ts)` → IP 점유 구간(tenancy)으로 한다.
3. **장애 격리.** Suricata 프로세스·설정 오류·부하가 Zeek 경로(자산 식별·탐지·전송)에 영향을 주지 않는다. 별도 프로세스, 별도 패킷 복사, 별도 전송 스트림.
4. **연결 결합 키는 Community ID.** Zeek `uid`와 Suricata `flow_id`는 서로 모르므로, 5-tuple 표준 해시인 Community ID로 잇는다.
5. **설정 원천은 하나.** 자산 대역(`AssetID::asset_nets`)과 Suricata `HOME_NET`을 같은 값에서 생성한다.

---

## 2. 전체 구조

```
                         ┌──────────────────────── 센서 ─────────────────────────────┐
 미러 트래픽 ─┬─ AF_PACKET │ [Zeek 워커]                                                │
 (eth1)       │ fanout A  │  ├ scripts/ (AssetID)  ─▶ asset_signal.log ─┐              │
              │           │  ├ nsm_rules (탐지)     ─▶ notice.log 등    ├─┐            │
              │           │  └ 기본 로그            ─▶ conn/dns/http…   ─┘ │            │
              │           │                                              ▼            │
              │           │                                   [수집 에이전트(shipper)] ──mTLS──▶ Manager
              │           │                                    스트림별 on/off, spool   │        ├ 자산 판정(엔티티 리졸루션)
              └─ AF_PACKET │ [Suricata] (선택, 기본 off)                  ▲            │        ├ 경보 ↔ 자산 결합 (ip, ts)
                fanout B  │  └ eve-alert.json, eve-stats.json ──────────┘            │        └ 경보 ↔ Zeek 로그 (community_id)
                          │                                                           │
                          │ [센서 설정 렌더러] sensor.yaml ─▶ zeek 설정 / suricata.yaml / 전송 스트림 설정 │
                          └───────────────────────────────────────────────────────────┘
                                            ▲ Manager가 sensor.yaml 배포 (on/off 포함)
```

- 패킷 복사: Zeek과 Suricata가 **서로 다른 AF_PACKET fanout 그룹 ID**를 쓰면 커널이 두 그룹에 각각 전체 트래픽을 준다. 서로의 부하·장애가 패킷 분배에 영향을 주지 않는다.
- CPU: 엔진별로 코어를 나눠 고정(pinning)한다. Suricata off 시 해당 코어는 비워 두거나 Zeek 워커에 줄 수 있다(재배치는 Zeek 재시작이 필요하므로 기본은 비워 둠).
- PoC(pcap) 모드에서는 같은 pcap을 두 엔진이 각각 읽는다(`zeek -r`, `suricata -r`).

### 2.1 엔진 역할 분담

| 기능 | Zeek | Suricata |
|---|---|---|
| 자산 신호(`asset_signal`) | **담당** | 하지 않음 (3단계에서 선택적 어댑터만 검토, 7장) |
| 행위·상관 탐지 (nsm_rules notice) | **담당** | — |
| 시그니처 탐지 (알려진 공격·악성코드·정책 위반) | — | **담당** (`alert`) |
| 프로토콜 메타데이터 (conn/dns/http/tls…) | **담당** | 기본 off (중복) |
| 센서 상태 (패킷 손실 등) | capture_loss, stats | `stats` (kernel_drops 등) |

---

## 3. on/off 설계

### 3.1 설정 모델 (`sensor.yaml`, Manager가 배포)

```yaml
sensor_id: sensor-01
interfaces: [eth1]
asset_nets: [10.0.0.0/8, 172.20.0.0/16]   # Zeek AssetID::asset_nets 와 Suricata HOME_NET 공통 원천
community_id_seed: 0                       # Suricata eve community-id-seed 와 Zeek(NSM::community_id_seed, CommunityID::seed) 공통 원천

zeek:
  asset_id:
    enabled: true                          # 기존 AssetID::enable_* 옵션은 그대로 유지

suricata:
  enabled: false                           # ★ 엔진 전체 on/off (기본 off)
  workers: 2                               # 코어 수
  outputs:
    alert: true
    stats: true                            # 센서 상태(패킷 손실) 전송용
    anomaly: false
    protocol_logs: false                   # http/dns/tls/flow — Zeek와 중복, 기본 off
  alert_fields:
    app_layer: false                       # 경보에 URL 등 앱 계층 값 포함 여부 (개인정보, 8장)
    payload: false                         # 페이로드·패킷 원문
    rule_metadata: true                    # MITRE 태그 등 룰 metadata
  rules:
    files: [suricata.rules, local.rules]   # suricata-update 산출물(카테고리 기본값은 disable.conf, 4.1) + 사내 룰
    threshold: true                        # 경보 폭주 억제 (threshold.config, 4.1)

transport:
  streams:                                 # 전송 스트림별 on/off (엔진이 켜져 있어도 전송만 끌 수 있음)
    asset_signal: true
    zeek_notice: true
    suricata_alert: true
    suricata_stats: true
```

**실제 동작 여부 = `suricata.enabled` AND 해당 출력 on AND `transport.streams.<스트림>` on.**
예) 룰 튜닝 기간에는 `suricata.enabled: true`, `suricata_alert: false`로 센서 로컬에만 경보를 쌓고 Manager로는 보내지 않는다.

### 3.2 on/off 단위와 반영 방식

| 단위 | 방법 | 재시작 | 영향 범위 |
|---|---|---|---|
| Suricata 엔진 전체 | systemd 유닛 start/stop + shipper 입력 추가/제거 | Suricata만 | Zeek 무영향 |
| 룰 카테고리·SID | `suricata-update`(enable/disable/modify.conf) → 유닛 소켓 `reload-rules` | 없음 | Suricata |
| eve 출력 종류·필드 | 렌더러가 suricata.yaml 재생성 → Suricata 재시작 | Suricata만 | Suricata |
| 전송 스트림 | shipper 설정 reload | 없음 | 해당 스트림 |
| AssetID 신호 소스 | 기존 Config 프레임워크 `option enable_*` | 없음 | Zeek (기존과 동일) |

### 3.3 상태 전이 (센서 에이전트)

```
 OFF ──enable──▶ 설정 렌더 ─▶ 룰 준비(suricata-update) ─▶ suricata -T (설정 검사) ─┬─ 실패 ─▶ OFF + 오류 보고
                                                                                     └─ 성공 ─▶ 기동 ─▶ 상태 정상 ─▶ shipper 입력 추가 ─▶ ON
 ON ──disable──▶ shipper가 eve 파일을 끝까지 읽음(drain) ─▶ 입력 제거 ─▶ Suricata 정지 ─▶ OFF
 ON ──비정상 종료──▶ systemd 재시작(횟수 제한) ─▶ 한도 초과 시 FAILED + Manager 보고 (Zeek은 계속 동작)
```

- 상태 보고(heartbeat)에 엔진별 `enabled / running / rules_loaded / rule_version / kernel_drops` 포함 → Manager 센서 화면에서 "설정상 on인데 실제 off" 같은 불일치를 드러낸다.
- **off일 때 회귀 보장:** Suricata 관련 설정·파일·스트림이 전혀 생성되지 않아야 하며, 기존 출력과 바이트 단위로 같아야 한다(10장 테스트).

---

## 4. Suricata 설정 구성

배포본 `suricata.yaml`은 고치지 않는다. 렌더러(`tools/render_config.py`)가 **배포본을 읽어 필요한 부분만 바꾼 전체 설정**을 새로 쓴다.

**include 파일을 쓰지 않는 이유 (8.0.6에서 확인):** Suricata `--include`는 include 파일에 있는 **최상위 항목을 통째로
교체**한다(로그: `Configuration node 'vars' redefined`). 하위 키 단위로 합치지 않으므로, include에
`vars.address-groups.HOME_NET`만 쓰면 `HTTP_PORTS`, `DC_SERVERS` 등 나머지 주소·포트 그룹 30여 개가 모두 사라지고
그 변수를 쓰는 룰이 깨진다. `stats`도 같은 이유로 배포본의 나머지 값을 잃는다. 결국 include를 쓰더라도 배포본의 해당
항목 전체를 복사해야 하므로, 처음부터 배포본을 읽어 전체 설정을 만드는 쪽이 단순하고 검증하기 쉽다.
(목록인 `outputs`는 통째 교체가 오히려 원하는 동작이다. 배포본 기본 eve-log는 프로토콜 로그 34종을 켜 둔다.)

렌더러가 바꾸는 것 (나머지는 배포본 값 그대로):

| 키 | 값 |
|---|---|
| `vars.address-groups.HOME_NET` | `asset_nets` (비면 RFC1918) |
| `default-rule-path`, `rule-files` | 룰 디렉터리, `suricata.rules` + `local.rules` |
| `threshold-file` | `rules.threshold`가 on일 때 |
| `outputs` | **eve-log로 통째 교체**: 경보 `eve-alert.json`, 통계 `eve-stats.json`, (켰을 때만) 기타 `eve-other.json` (아래) |
| `stats.enabled`, `stats.interval` | `outputs.stats`, `transport.stats_interval` |
| `af-packet` | `interfaces`마다 `cluster-id`(Zeek fanout과 다름), `cluster_flow`, `workers` |

```yaml
outputs:
- eve-log:                   # 경보: 수집 에이전트가 suricata_alert 로 Manager에 바로 보냄
    enabled: yes
    filetype: regular
    filename: eve-alert.json
    community-id: yes        # Zeek 로그와 결합 키
    community-id-seed: 0     # community_id_seed
    types:
    - alert:
        payload: no          # alert_fields.payload
        payload-printable: no
        packet: no
        http-body: no
        http-body-printable: no
        tagged-packets: no
        metadata:
          app-layer: no      # alert_fields.app_layer
          flow: no
          rule: {metadata: yes, raw: no}   # alert_fields.rule_metadata
- eve-log:                   # 통계: suricata_stats (센서 상태)
    enabled: yes
    filetype: regular
    filename: eve-stats.json
    types:
    - stats: {totals: yes, threads: no, deltas: yes}
# outputs.anomaly·protocol_logs 를 켜면 eve-other.json(Community ID 포함)에 쓴다. 센서 로컬 조사용이고 전송하지 않는다
```

경보와 통계를 나눈 이유: 가는 곳이 다르다(경보는 Manager 탐지 흐름, 통계는 센서 상태). 한 파일이면 수집 에이전트가 줄마다
`event_type`을 봐야 하고, 경보가 몰릴 때 통계가 늦는다. 렌더러는 스트림별 입력 파일을 `transport/streams.json`의 `inputs`에 적는다.

### 4.1 룰 범위·경보 억제 기본값

nsm 설계 6.1절(Zeek 행위 탐지와 겹치지 않게)을 `suricata/update/disable.conf`에 옮겼다. 공개 데이터(CIC-IDS2017) 측정(nsm 설계 S5) 뒤 확정한다.

| 끔 | 이유 |
|---|---|
| IP 평판 목록(ciarmy, compromised, drop, dshield, tor, botcc) | IOC는 Zeek `IOC_Match`로 한 곳에서 관리 |
| dns, policy·info·hunting 등 정보성, ja3, adware_pup, dos, scada | Zeek 탐지와 겹치거나 정보성(고객 요청·OT 망이면 켬) |
| ET SCAN 중 횟수 조건(`threshold`·`detection_filter`) 룰 | Zeek 포트·호스트 스캔, 비밀번호 대입과 겹침. 도구 지문 룰은 켬 |
| `heartbleed` | Zeek `TLS_Heartbleed`와 겹침 |
| Suricata 기본 이벤트 룰(`msg:"SURICATA ..."`, 약 370개) | suricata-update가 기본으로 넣는 디코더·스트림·앱 계층 이상 룰. 미러 구간은 패킷 누락이 흔해 계속 나고 Zeek `weird.log`와 겹침 |

통합 테스트 5번이 ET 파일 이름을 흉내 낸 표본(`tests/rules/et_sample`)으로 켜지는 룰을 확인한다. 실제 ET Open 파일 이름·룰 수는 S5에서 확인한다.

`suricata/threshold.config` 기본: 자체 횟수 조건이 없는 룰에 (룰, 출발지, 목적지)마다 60초에 1건(`sig_id 0`, `track by_both`, `type limit`).
나머지 반복은 Manager 사건 묶기가 모은다. Suricata 8.0.6에서 확인한 동작(`demo.pcap`, 3회):

| 룰 | threshold 없음 | 기본 줄 |
|---|---|---|
| 자체 조건 없음(패킷마다) | 66건 | 27\~29건 |
| 자체 `threshold: type threshold, count 5` | 4\~6건 | 4\~6건(룰 조건 우선, 기동 시 룰마다 경고 한 줄) |

**표기 보존:** Suricata는 모든 값을 문자열로 다룬다. PyYAML 기본 동작으로 읽고 쓰면 `yes`가 `true`로, 빈 값이 `null`
문자열로 바뀌므로, 암시적 타입 변환을 끈 로더·덤퍼로 문자열 그대로 읽고 쓴다.

**검증:** 통합 테스트(`tests/e2e.sh` 1번)가 배포본과 생성본을 Suricata가 실제로 읽은 값(`suricata --dump-config`)으로
비교해, 위 표의 키 외에는 바뀐 것이 없는지 확인한다. Suricata 버전을 올릴 때 이 테스트로 배포본 변화를 잡는다.

- 운영 모드: **IDS(패시브)만.** 미러 트래픽이므로 IPS(차단)·8.0의 방화벽 모드는 범위 밖.
- 체크섬: PoC pcap 실행 시 `-k none`(Zeek `-C`와 동일 취지).
- 룰: `suricata-update -c suricata/update/update.yaml` 산출물 `suricata.rules` + `local.rules`(사내 룰, SID 9000000~). 룰 버전(해시·날짜)을 상태 보고에 포함.
- 설정 검사: 기동 전 `suricata -T`. 실패하면 Suricata만 끄고 AssetID 경로는 그대로 둔다(PoC `run_poc.sh`도 같은 순서).

---

## 5. 메타데이터 전송

### 5.1 스트림 추가

| 스트림 | 원천 | 필터 | 기본 |
|---|---|---|---|
| `asset_signal` (기존) | Zeek | — | on |
| `zeek_notice` 등 (기존) | Zeek | 기존 선별 전송 기준 | on |
| **`suricata_alert`** | eve-alert.json | `event_type == "alert"` | Suricata on일 때 on. Manager가 탐지로 바꿈(nsm 설계 3장) |
| **`suricata_stats`** | eve-stats.json | `event_type == "stats"`, 1분 1건으로 축약 | Suricata on일 때 on |

- 기존 수집 에이전트에 eve 파일 입력을 두고(파일 = 스트림, `transport/streams.json`의 `inputs`) 보낸다. 전송 경로(mTLS, spool, 재전송)는 기존 것을 그대로 쓴다.
- spool 상한은 스트림별로 둔다. 경보 폭주 시 Suricata 스트림이 spool을 채워 **`asset_signal` 전송을 막지 않도록** 스트림 우선순위를 `asset_signal`·Zeek > Suricata로 한다.

### 5.2 공통 전송 envelope

엔진이 달라도 Manager가 같은 방식으로 받도록 바깥 필드를 맞춘다(안쪽 `data`는 원본 유지).

```json
{
  "sensor_id": "sensor-01",
  "engine": "suricata",            // "zeek" | "suricata"
  "stream": "suricata_alert",
  "ts": "2026-11-10T09:12:03.123456Z",
  "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
  "data": {                         // eve alert에서 선별한 필드
    "flow_id": 1234567890, "src_ip": "10.10.0.101", "src_port": 51234,
    "dest_ip": "10.10.1.10", "dest_port": 445, "proto": "TCP", "app_proto": "smb",
    "alert": { "action": "allowed", "signature_id": 2024217, "rev": 3,
               "signature": "ET EXPLOIT ...", "category": "...", "severity": 1,
               "metadata": { "mitre_technique_id": ["T1210"] } }
  }
}
```

Zeek 쪽 `community_id`(nsm #137에서 반영): nsm_rules가 conn(`community-id-logging`)과 연결 단위 선별 전송 로그(kerberos·ntlm·smb·dce_rpc·rdp·ssh·ssl·http),
근거(`evidence.log`)에 넣는다. conn.log는 Manager로 요약만 가므로, Manager는 선별 전송 로그와 근거로 경보의 연결을 찾는다.
seed는 `community_id_seed` 하나로 맞춘다. 렌더러가 Suricata eve의 `community-id-seed`와 Zeek 설정(`zeek/nsm_sensor.zeek`)의
`NSM::community_id_seed`(nsm_rules를 함께 로드할 때, `@ifdef`)·`CommunityID::seed`(Suricata on일 때)에 같은 값을 쓴다. `nsm_sensor.zeek`는 nsm_rules 뒤에 로드한다.
`alert.source`·`alert.target`(룰에 `target` 키워드가 있을 때)도 보낸다. Manager가 출발지·대상을 정할 때 먼저 쓴다(nsm 설계 3.5).

---

## 6. Manager 결합 (경보 ↔ 자산 ↔ Zeek 로그)

### 6.1 경보 → 자산

리졸버가 이미 만드는 **IP 점유 구간(tenancy: ip, 시작, 끝 → 자산)** 을 그대로 조회 테이블로 쓴다.

```
for 경보 in suricata_alert:
    for 방향, ip in (src, dest):
        구간 = tenancy[ip] 중 시작 - grace ≤ 경보.ts ≤ 끝 + grace 인 것   (grace 기본 5분)
        자산 = 구간 ? 구간.asset : (ip ∈ asset_nets ? "미식별 내부 IP" : "외부")
    표시: "laptop-sales07 (windows 10/11) → dc01 (도메인 컨트롤러)" + 원래 IP
```

- 같은 IP가 DHCP로 재할당된 경우에도 경보 시각 기준 점유 구간을 고르므로 **그 시각의 단말**에 붙는다(기존 IP 재사용 처리의 이점).
- 실시간 운영에서는 판정이 계속 갱신되므로, 경보에는 결합 시점의 `asset_id`를 저장하고 이후 자산 병합 시 `asset_id` 별칭 테이블로 따라간다.

### 6.2 경보 → Zeek 로그·탐지

- `community_id`로 선별 전송 연결 로그(ssl·http·kerberos 등)와 근거를 찾아 경보에 목적지 이름·uid를 붙인다(Suricata 프로토콜 로그를 끈 대신 Zeek 메타데이터로 맥락 제공).
- 같은 `community_id`·같은 단계에 Zeek 탐지와 Suricata 경보가 함께 있으면 **한 탐지로 보인다**(이중 경보 방지).
- 단계·위험도·예외·사건 묶기·통합 상관은 nsm [SURICATA_INTEGRATION_DESIGN.md](https://github.com/kwsjjang8901-ship-it/nsm/blob/main/docs/SURICATA_INTEGRATION_DESIGN.md) 3\~6장을 따른다.

### 6.3 자산 기반 우선순위 (3단계)

| 조건 | 처리 |
|---|---|
| 목적지 자산 역할이 DC·DB·파일 서버 | 심각도 상향 |
| 룰 대상 OS와 자산 OS 불일치 (Windows 익스플로잇 → Linux 자산) | 하향 또는 "대상 불일치" 표시 |
| 출발지가 다중 머신 계정 인증 IP (SPEC 4.6) | 상향 (NTLM 릴레이 의심과 겹침) |

---

## 7. 양방향 연계 (3단계, 선택)

| 방향 | 내용 | 기본 |
|---|---|---|
| 자산 → Suricata | Manager의 자산 역할로 Suricata 주소 그룹(`DC_SERVERS`, `DNS_SERVERS`, `HTTP_SERVERS`, `SQL_SERVERS`, `SMTP_SERVERS`)을 생성해 suricata.yaml에 반영 → 룰 정확도 향상, 오탐 감소. 변경 시 `reload-rules` | off |
| Suricata → 자산 신호 | ET POLICY/INFO 계열 경보(특정 소프트웨어·원격제어 도구 사용 등)를 `software`·`device` 신호로 바꾸는 어댑터(source=`suricata`, 낮은 신뢰도). 자산 판정 키로는 쓰지 않음 | off |

후자는 Zeek이 이미 같은 정보를 내는 경우가 많아, 실제 효과(새로 얻는 정보 비율)를 측정한 뒤 결정한다.

---

## 8. 개인정보·보안

SPEC 8장 원칙(URL·쿼리 값, 인증 응답값 미수집)을 Suricata에도 적용한다.

- 기본값: `payload`·`packet`·`http-body` 끔, 경보 `metadata.app-layer` 끔 → 경보에 URL·헤더·본문 값이 실리지 않는다.
- 조사용으로 켜야 하면 센서 로컬 보관만 허용하고 전송은 끄는 조합(`alert_fields.app_layer: true` + `suricata_alert`는 필드 제거 후 전송)을 쓴다.
- 룰 소스: ET Open(무료) 기본. ET Pro 등 상용 룰은 라이선스·배포 범위 확인 후.

---

## 9. 저장소 구조 (1단계 PoC 구현)

자산 식별(AssetID)과 저장소를 나눴다. 이 저장소는 AssetID의 산출물(`assets.json`, Zeek 로그)만 입력으로 쓰고,
AssetID 코드를 고치지 않는다. 센서 패키지는 nsm `nsm_rules/asset-id/`에 있고, PoC 실행(`run_poc.sh -a`)은 `claudtest2`의 실행 도구·리졸버를 쓴다.

```
config/sensor.example.yaml   센서 설정 예시 (on/off 원천, 출시 기본값 off)
suricata/
  rules/local.rules          사내 룰 (SID 9000000~)
  threshold.config           경보 폭주 억제 기본값 (4.1)
  update/                    suricata-update 설정·enable/disable/modify.conf (disable.conf = 룰 범위 기본값, 4.1)
tools/
  sensor_config.py           설정 로드·검증·실제 동작(effective) 계산
  render_config.py           sensor.yaml -> zeek 설정 / suricata.yaml / 전송 스트림
  eve_envelope.py            eve 파일(경보·통계) -> 전송 스트림(envelope JSONL), 필드 허용 목록, stats 축약
  alert_join.py              경보 + assets.json (+ Zeek conn.log) -> 자산 컨텍스트 경보, 리포트
  run_poc.sh                 위 단계를 pcap 하나로 실행
tests/
  unit/                      단위 테스트 (설정, 렌더, envelope, 결합)
  rules/test.rules           결정적 테스트 룰 (SID 9900000~)
  e2e.sh                     Docker 통합 테스트 (설정 충실도, on/off 회귀, 결합)
```

`run_poc.sh` 흐름:

```
[1/4] 센서 설정 렌더      render_config.py  (on이면 이미지의 배포본 suricata.yaml을 꺼내 전체 설정 생성)
[2/4] AssetID            claudtest2/tools/run_poc.sh -z nsm_sensor.zeek  -> assets.json, conn.log(community_id)
[3/4] Suricata           suricata -T (실패 시 Suricata만 건너뜀) -> suricata -r <pcap> -k none
[4/4] 전송·결합           eve_envelope.py -> transport/*.jsonl,  alert_join.py -> alerts.*
```

off이면 3·4단계를 건너뛰고 Suricata 관련 파일을 하나도 만들지 않는다. Zeek 설정에도 Community ID를 넣지 않아
conn.log와 AssetID 결과가 AssetID 단독 실행과 같다(통합 테스트 4번).

---

## 10. 테스트·검증

| 구분 | 항목 | 상태 |
|---|---|---|
| 설정 | 키 검증(오타·타입·CIDR·fanout 충돌·seed 범위), on/off AND 계산, 출력·필드 옵션별 생성 결과(경보·통계·기타 파일), seed, 표기 보존 | 단위 테스트 |
| 경보·통계 분리 | `eve-alert.json`에는 경보만, `eve-stats.json`에는 통계만, `eve.json` 없음 | 통합 2 |
| 룰 범위 기본값 | ET 표본에 suricata-update + disable.conf → 켜지는 룰이 기대한 4개뿐 | 통합 5 |
| 설정 충실도 | 배포본 대비 의도한 키 외 변경 없음 (`--dump-config` 비교) | 통합 1 |
| off 회귀 | Suricata 생성물 없음, conn.log 형식 그대로, assets.json·asset_signal.log가 AssetID 단독 실행과 같음 | 통합 4 |
| IP 재사용 | `demo.pcap` 10.10.0.120 경보 2건이 시각에 따라 laptop-sales07 / galaxy-s24에 붙음 | 통합 2, 단위 |
| 중요 서버·OS 불일치 | Kerberos 경보 → dc01(도메인 컨트롤러) 표시, Windows 룰 → Linux 자산 불일치 표시 | 통합 2, 단위 |
| Zeek 결합 | 모든 경보에 Community ID로 Zeek uid 연결 | 통합 2 |
| 결합 정확도 | `extras.pcap` AhnLab V3 통신 경보가 출발지 자산에 붙음 | 통합 3 |
| 전송 | 필드 허용 목록(앱 계층·페이로드 기본 제외, `source`·`target` 포함), 꺼진 스트림 미생성, stats 축약, 파일 여러 개 입력 | 단위 |
| 장애 격리 | 설정 검사 실패 시 Suricata만 건너뜀 | `run_poc.sh` 구현, 자동 테스트 없음 |
| 부하 | 실시간에서 Zeek 단독 vs Zeek+Suricata의 패킷 손실·CPU 비교 (PLAN V4와 함께) | 2단계 |
| 전송 우선순위 | 경보 폭주 시 `asset_signal` 전송 지연 없음 | 2단계 (수집 에이전트) |

**확인된 주의점 (pcap 모드 threshold):** pcap 모드에서 Suricata는 경보를 시간 순서대로 내지 않는다. 앱 계층 룰이 함께
있으면 IP 전용 룰의 13:01 경보가 09:12 경보보다 먼저 기록되고, 이때 `threshold: type limit`의 시간 창이 앞선 09:12 경보를
눌렀다(테스트 룰 9900004에서 확인, 룰 하나만 있으면 정상). 그래서 테스트 룰에는 threshold를 쓰지 않았고, 결합 도구는 경보를
시각순으로 다시 정렬한다. 실시간 모드에서도 같은 현상이 있는지는 2단계에서 확인한다.
0.3에서 `threshold.config`에 기본 줄(4.1)을 넣은 뒤에도 통합 테스트 2번(IP 재사용)은 통과한다.

---

## 11. 단계별 계획

| 단계 | 범위 | 산출물 |
|---|---|---|
| 1. PoC (**완료**) | pcap 모드, `run_poc.sh -S on`, 설정 렌더러, 전송 envelope, 경보-자산 결합 리포트 | 이 저장소, 단위·통합 테스트 |
| 2. 센서 통합 | `sensor.yaml` 렌더러, systemd 유닛, AF_PACKET 공존, shipper 스트림·우선순위, 상태 보고 | 센서 패키지, 운영 측정(부하·손실) |
| 3. 연계 고도화 | 자산 역할 → 주소 그룹, 자산 기반 우선순위, notice·경보 사건 묶기, 선택적 신호 어댑터 | Manager 요구사항(SRS) |

## 12. 결정이 필요한 사항

| 항목 | 선택지 | 제안 |
|---|---|---|
| Suricata 버전 | 7.0.x / 8.0.x | **8.0.x로 결정, PoC는 8.0.6.** 7.0은 2026-07-07에 EOL(마지막 7.0.17), 보안 패치가 더 나오지 않음. 이 설계는 AF_PACKET·eve alert만 쓰므로 8.0의 비호환 변경(PF_RING 플러그인 분리, DNS 로그 형식 v3, `stats.whitelist`→`stats.score`)의 영향이 거의 없음 |
| 룰 소스 | ET Open / ET Pro / 사내 룰 | ET Open + 사내 룰로 시작 |
| Zeek Community ID | nsm_rules에서 로드 / Manager 계산 | **결정·반영(nsm #137):** nsm_rules가 conn·연결 단위 선별 전송 로그·근거에 넣음 |
| 경보 전달 방식 | Zeek가 받아 notice로 / Manager로 바로 | **결정(2026-11-24): Manager로 바로**(nsm 설계 방식 B) |
| 수집 에이전트 | eve 입력 추가 가능 여부, 스트림 우선순위 지원 여부 | 담당 팀 확인 필요 |
| 센서 자원 | Suricata용 코어·메모리 할당 | 실시간 측정(V4) 후 확정, 기본 off로 출시 |
