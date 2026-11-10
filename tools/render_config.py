#!/usr/bin/env python3
"""sensor.yaml -> 엔진별 설정 생성.

생성물 (--out DIR):
  state.json                 실제로 켜지는 것(엔진, 출력, 전송 스트림)
  transport/streams.json     수집 에이전트가 읽을 스트림 on/off
  zeek/nsm_sensor.zeek       Zeek 설정 (AssetID 자산 대역, Suricata on이면 Community ID)
  suricata/suricata.yaml     Suricata on일 때만. 배포본 suricata.yaml(--base)을 읽어 필요한 부분만 바꾼 전체 설정

Suricata off이면 suricata/ 아래 생성물을 지운다(이전 실행의 잔여 설정으로 엔진이 뜨지 않게).

배포본 suricata.yaml을 직접 고치지 않고 '읽어서 새로 쓰는' 이유 (Suricata 8.0.6에서 확인):
  Suricata --include는 최상위 항목을 통째로 교체한다. include에 vars.address-groups.HOME_NET만 쓰면
  나머지 주소·포트 그룹(HTTP_PORTS 등)이 모두 사라져 룰이 깨진다. 그래서 배포본 전체를 읽어 필요한
  키만 바꾼 전체 설정을 만든다(docs/DESIGN.md 4장).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sensor_config as sc  # noqa: E402

YAML_HEADER = "%YAML 1.1\n---\n# render_config.py 가 생성한 파일입니다. 직접 고치지 말고 sensor.yaml을 고치세요.\n"


def eve_output(cfg):
    s = cfg["suricata"]
    out, fields = s["outputs"], s["alert_fields"]
    types = []
    if out["alert"]:
        types.append({"alert": {
            "payload": fields["payload"],
            "payload-printable": fields["payload"],
            "packet": fields["payload"],
            "http-body": False,
            "http-body-printable": False,
            "tagged-packets": False,
            "metadata": {
                "app-layer": fields["app_layer"],
                "flow": False,
                "rule": {"metadata": fields["rule_metadata"], "raw": False},
            },
        }})
    if out["anomaly"]:
        types.append({"anomaly": {"enabled": True}})
    if out["protocol_logs"]:
        types.extend(sc.PROTOCOL_LOG_TYPES)
    if out["stats"]:
        types.append({"stats": {"totals": True, "threads": False, "deltas": True}})
    return {"eve-log": {
        "enabled": True,
        "filetype": "regular",
        "filename": "eve.json",
        "community-id": True,
        "community-id-seed": 0,
        "types": types,
    }}


def suricata_yaml(cfg, base, rule_path, threshold_file):
    """배포본 설정(base, dict)에 센서 설정을 반영한 전체 설정을 돌려준다."""
    s = cfg["suricata"]
    y = dict(base)
    vars_ = dict(y.get("vars") or {})
    groups = dict(vars_.get("address-groups") or {})
    groups["HOME_NET"] = sc.home_net(cfg)
    groups["EXTERNAL_NET"] = "!$HOME_NET"
    vars_["address-groups"] = groups
    y["vars"] = vars_

    y["default-rule-path"] = rule_path
    y["rule-files"] = list(s["rules"]["files"])
    if s["rules"]["threshold"] and threshold_file:
        y["threshold-file"] = threshold_file
    else:
        y.pop("threshold-file", None)

    # 출력은 eve-log 하나만 (배포본의 fast.log, 기본 eve 프로토콜 로그 등은 모두 제거)
    y["outputs"] = [eve_output(cfg)]

    stats = dict(y.get("stats") or {})
    stats["enabled"] = bool(s["outputs"]["stats"])
    stats["interval"] = int(cfg["transport"]["stats_interval"])
    y["stats"] = stats

    if cfg["interfaces"]:
        y["af-packet"] = [{
            "interface": iface,
            "cluster-id": s["cluster_id"] + i,
            "cluster-type": "cluster_flow",
            "defrag": True,
            "threads": s["workers"],
        } for i, iface in enumerate(cfg["interfaces"])]
    return y


def _suricata_yaml_io():
    """Suricata 설정을 값 그대로 읽고 쓰는 YAML 로더·덤퍼.

    Suricata는 모든 값을 문자열로 다룬다. PyYAML 기본 동작(yes -> True -> 'true', 빈 값 -> None -> 'null')을
    쓰면 배포본 값의 표기가 바뀌므로, 암시적 타입 변환을 모두 끄고 문자열로만 읽고 쓴다.
    빈 값은 ''로 읽혀 'key:' 그대로 다시 쓰인다.
    """
    import yaml

    class Loader(yaml.SafeLoader):
        yaml_implicit_resolvers = {}

    class Dumper(yaml.SafeDumper):
        yaml_implicit_resolvers = {}

    return yaml, Loader, Dumper


def stringify(n):
    """센서 설정에서 넣은 값(bool, int)을 Suricata 표기 문자열로 바꾼다."""
    if isinstance(n, dict):
        return {str(k): stringify(v) for k, v in n.items()}
    if isinstance(n, list):
        return [stringify(v) for v in n]
    if isinstance(n, bool):
        return "yes" if n else "no"
    if n is None:
        return ""
    return str(n)


def zeek_script(cfg, eff):
    lines = ["# render_config.py 가 생성. 센서 설정(sensor.yaml) 반영"]
    if cfg["asset_nets"]:
        lines.append("redef AssetID::asset_nets = { %s };" % ", ".join(str(n) for n in cfg["asset_nets"]))
    if eff["suricata"]:
        # Suricata 경보와 Zeek 로그를 잇는 키. Suricata off이면 conn.log를 지금과 같게 두려고 로드하지 않는다.
        lines.append("@load policy/protocols/conn/community-id-logging")
    return "\n".join(lines) + "\n"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def render(cfg, out_dir, base_path=None, rule_path="/var/lib/suricata/rules", threshold_file=None):
    eff = sc.effective(cfg)
    state = {"sensor_id": cfg["sensor_id"], **eff,
             "zeek_asset_id": cfg["zeek"]["asset_id"]["enabled"],
             "home_net": sc.home_net(cfg)}
    write(os.path.join(out_dir, "state.json"), json.dumps(state, ensure_ascii=False, indent=1) + "\n")
    write(os.path.join(out_dir, "transport", "streams.json"),
          json.dumps({"stats_interval": cfg["transport"]["stats_interval"], "streams": eff["streams"],
                      "alert_fields": cfg["suricata"]["alert_fields"]}, indent=1) + "\n")
    write(os.path.join(out_dir, "zeek", "nsm_sensor.zeek"), zeek_script(cfg, eff))

    sur_yaml = os.path.join(out_dir, "suricata", "suricata.yaml")
    if not eff["suricata"]:
        if os.path.exists(sur_yaml):
            os.remove(sur_yaml)
        return state

    if not base_path:
        raise sc.ConfigError("Suricata가 켜져 있으면 배포본 suricata.yaml 경로(--base)가 필요합니다")
    yaml, Loader, Dumper = _suricata_yaml_io()  # Suricata 설정 생성에만 PyYAML 필요
    with open(base_path, encoding="utf-8") as f:
        base = yaml.load(f, Loader=Loader)
    y = stringify(suricata_yaml(cfg, base, rule_path, threshold_file))
    write(sur_yaml, YAML_HEADER + yaml.dump(y, Dumper=Dumper, sort_keys=False, default_flow_style=False,
                                            allow_unicode=True, width=1000))
    return state


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", required=True, help="sensor.yaml (또는 .json)")
    ap.add_argument("-o", "--out", required=True, help="생성물 디렉터리")
    ap.add_argument("--base", help="배포본 suricata.yaml (Suricata on일 때 필요)")
    ap.add_argument("--rule-path", default="/var/lib/suricata/rules", help="룰 디렉터리 (default-rule-path)")
    ap.add_argument("--threshold-file", help="threshold.config 경로")
    ap.add_argument("--suricata", choices=["on", "off"], help="설정 파일의 suricata.enabled를 이번 실행에서만 덮어씀")
    a = ap.parse_args(argv)
    try:
        cfg = sc.load(a.config)
        if a.suricata:
            cfg["suricata"]["enabled"] = a.suricata == "on"
        state = render(cfg, a.out, a.base, a.rule_path, a.threshold_file)
    except (sc.ConfigError, OSError) as e:
        print("설정 오류: %s" % e, file=sys.stderr)
        return 2
    on = [k for k, v in state["streams"].items() if v]
    print("Suricata: %s · 전송 스트림: %s" % ("on" if state["suricata"] else "off", ", ".join(on) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
