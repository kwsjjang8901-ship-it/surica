"""센서 설정(sensor.yaml) 로더.

Manager가 배포하는 센서 설정 하나에서 Zeek·Suricata·전송 설정을 모두 만든다.
이 모듈은 설정을 읽고 검증한 뒤, 실제로 켜지는 것(effective state)을 계산한다.

    실제 동작 = suricata.enabled AND 해당 출력 on AND transport.streams.<스트림> on

YAML 파일은 PyYAML이 필요하다. 확장자가 .json이면 표준 라이브러리만으로 읽는다.
"""

import copy
import ipaddress
import json
import os

DEFAULTS = {
    "sensor_id": "sensor-01",
    "interfaces": [],
    "asset_nets": [],
    "zeek": {
        "fanout_id": 99,            # Zeek AF_PACKET fanout 그룹 (Suricata cluster_id와 달라야 함)
        "asset_id": {"enabled": True},
    },
    "suricata": {
        "enabled": False,           # 엔진 전체 on/off (기본 off)
        "workers": 2,
        "cluster_id": 98,
        "outputs": {
            "alert": True,
            "stats": True,
            "anomaly": False,
            "protocol_logs": False,  # http/dns/tls/flow 등. Zeek와 중복이라 기본 off
        },
        "alert_fields": {
            "app_layer": False,      # 경보에 URL·헤더 등 앱 계층 값
            "payload": False,        # 페이로드·패킷 원문
            "rule_metadata": True,   # 룰 metadata (MITRE 태그 등)
        },
        "rules": {
            "files": ["suricata.rules", "local.rules"],
            "threshold": True,
        },
    },
    "transport": {
        "streams": {
            "asset_signal": True,
            "zeek_notice": True,
            "suricata_alert": True,
            "suricata_stats": True,
        },
        "stats_interval": 60,        # suricata_stats 전송 간격(초)
    },
}

# Suricata 프로토콜 로그를 켰을 때 쓰는 eve 타입
PROTOCOL_LOG_TYPES = ["http", "dns", "tls", "smb", "ssh", "flow"]

# 스트림 -> 그 스트림을 만드는 Suricata 출력
SURICATA_STREAMS = {"suricata_alert": "alert", "suricata_stats": "stats"}


class ConfigError(ValueError):
    pass


def _merge(base, over, path=""):
    """over를 base에 덮어쓴다. 모르는 키는 오타일 가능성이 커서 오류로 본다."""
    out = copy.deepcopy(base)
    for k, v in over.items():
        where = "%s.%s" % (path, k) if path else k
        if k not in base:
            raise ConfigError("알 수 없는 설정 키: %s" % where)
        if isinstance(base[k], dict):
            if not isinstance(v, dict):
                raise ConfigError("%s 는 항목 묶음(mapping)이어야 합니다" % where)
            out[k] = _merge(base[k], v, where)
        else:
            out[k] = v
    return out


def _bool(cfg, *keys):
    node = cfg
    for k in keys:
        node = node[k]
    if not isinstance(node, bool):
        raise ConfigError("%s 는 true/false 여야 합니다 (값: %r)" % (".".join(keys), node))
    return node


def validate(cfg):
    for keys in (("suricata", "enabled"), ("zeek", "asset_id", "enabled")):
        _bool(cfg, *keys)
    for sect in ("outputs", "alert_fields"):
        for k in cfg["suricata"][sect]:
            _bool(cfg, "suricata", sect, k)
    for k in cfg["transport"]["streams"]:
        _bool(cfg, "transport", "streams", k)

    nets = cfg["asset_nets"]
    if not isinstance(nets, list):
        raise ConfigError("asset_nets 는 목록이어야 합니다")
    for n in nets:
        try:
            ipaddress.ip_network(str(n), strict=False)
        except ValueError:
            raise ConfigError("asset_nets 값이 대역(CIDR)이 아닙니다: %r" % n)

    s = cfg["suricata"]
    if not isinstance(s["workers"], int) or s["workers"] < 1:
        raise ConfigError("suricata.workers 는 1 이상의 정수여야 합니다")
    if s["cluster_id"] == cfg["zeek"]["fanout_id"]:
        raise ConfigError("suricata.cluster_id 와 zeek.fanout_id 가 같으면 두 엔진이 패킷을 나눠 갖게 됩니다")
    if not s["rules"]["files"]:
        raise ConfigError("suricata.rules.files 가 비어 있습니다")
    iv = cfg["transport"]["stats_interval"]
    if not isinstance(iv, (int, float)) or iv <= 0:
        raise ConfigError("transport.stats_interval 은 0보다 커야 합니다")
    return cfg


def from_dict(d):
    if d is None:
        d = {}
    if not isinstance(d, dict):
        raise ConfigError("설정 최상위는 항목 묶음(mapping)이어야 합니다")
    return validate(_merge(DEFAULTS, d))


def load(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if os.path.splitext(path)[1].lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError:
            raise ConfigError("YAML 설정을 읽으려면 PyYAML이 필요합니다 (pip install pyyaml). 또는 .json 설정을 쓰세요")
        data = yaml.safe_load(text)
    return from_dict(data)


def effective(cfg):
    """실제로 켜지는 것만 계산한다."""
    s = cfg["suricata"]
    on = s["enabled"]
    streams = {}
    for name, flag in cfg["transport"]["streams"].items():
        if name in SURICATA_STREAMS:
            flag = flag and on and s["outputs"][SURICATA_STREAMS[name]]
        elif name == "asset_signal":
            flag = flag and cfg["zeek"]["asset_id"]["enabled"]
        streams[name] = bool(flag)
    return {
        "suricata": on,
        "suricata_outputs": {k: (on and v) for k, v in s["outputs"].items()},
        "streams": streams,
    }


def home_net(cfg):
    """Suricata HOME_NET 값. asset_nets가 비면 RFC1918 사설 대역(Suricata 기본값과 같음)."""
    nets = cfg["asset_nets"] or ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    return "[%s]" % ",".join(str(n) for n in nets)


def main(argv=None):
    """셸 스크립트용: 설정에서 값 하나를 꺼낸다."""
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="센서 설정 조회")
    ap.add_argument("-c", "--config", required=True)
    ap.add_argument("--suricata", choices=["on", "off"], help="suricata.enabled 덮어쓰기")
    ap.add_argument("--get", required=True, choices=["suricata", "asset_nets", "sensor_id", "effective"])
    a = ap.parse_args(argv)
    try:
        cfg = load(a.config)
    except (ConfigError, OSError) as e:
        print("설정 오류: %s" % e, file=sys.stderr)
        return 2
    if a.suricata:
        cfg["suricata"]["enabled"] = a.suricata == "on"
    if a.get == "suricata":
        print("on" if cfg["suricata"]["enabled"] else "off")
    elif a.get == "asset_nets":
        print(",".join(str(n) for n in cfg["asset_nets"]))
    elif a.get == "sensor_id":
        print(cfg["sensor_id"])
    else:
        print(json.dumps(effective(cfg), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
