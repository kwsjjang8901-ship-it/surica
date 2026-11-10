"""센서 설정 로더·렌더러 테스트 (on/off, 검증, Suricata 설정 생성)."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import render_config as rc  # noqa: E402
import sensor_config as sc  # noqa: E402

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

# 배포본 suricata.yaml을 줄인 것: yes/no 표기, 빈 값, 기본 출력 여러 개
BASE_YAML = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    DC_SERVERS: "$HOME_NET"
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      types:
        - alert:
            tagged-packets: yes
        - http:
            extended: yes
        - dns
        - flow
  - stats:
      enabled: yes
stats:
  enabled: yes
  interval: 8
  exception-policy:
af-packet:
  - interface: eth0
    cluster-id: 99
  - interface: default
app-layer:
  protocols:
    dnp3:
      enabled: no
"""


class TestSensorConfig(unittest.TestCase):
    def test_defaults_off(self):
        cfg = sc.from_dict({})
        eff = sc.effective(cfg)
        self.assertFalse(eff["suricata"])
        self.assertFalse(eff["streams"]["suricata_alert"])
        self.assertFalse(eff["streams"]["suricata_stats"])
        self.assertTrue(eff["streams"]["asset_signal"])

    def test_effective_and(self):
        on = {"suricata": {"enabled": True}}
        self.assertTrue(sc.effective(sc.from_dict(on))["streams"]["suricata_alert"])
        # 엔진 on + 전송 off -> 스트림 off
        cfg = sc.from_dict({"suricata": {"enabled": True}, "transport": {"streams": {"suricata_alert": False}}})
        self.assertFalse(sc.effective(cfg)["streams"]["suricata_alert"])
        # 엔진 on + 출력 off -> 스트림 off
        cfg = sc.from_dict({"suricata": {"enabled": True, "outputs": {"stats": False}}})
        eff = sc.effective(cfg)
        self.assertFalse(eff["streams"]["suricata_stats"])
        self.assertTrue(eff["streams"]["suricata_alert"])
        # AssetID off -> asset_signal off
        cfg = sc.from_dict({"zeek": {"asset_id": {"enabled": False}}})
        self.assertFalse(sc.effective(cfg)["streams"]["asset_signal"])

    def test_validation(self):
        bad = [
            {"suricata": {"enable": True}},                       # 오타
            {"suricata": {"enabled": "yes"}},                     # 문자열
            {"suricata": {"cluster_id": 99}},                     # zeek fanout_id와 같음
            {"asset_nets": ["10.0.0.0/33"]},
            {"asset_nets": "10.0.0.0/8"},
            {"suricata": {"workers": 0}},
            {"suricata": {"outputs": True}},
            {"transport": {"stats_interval": 0}},
            {"suricata": {"rules": {"files": []}}},
            ["not", "a", "mapping"],
        ]
        for b in bad:
            with self.subTest(b=b), self.assertRaises(sc.ConfigError):
                sc.from_dict(b)

    def test_home_net(self):
        self.assertEqual(sc.home_net(sc.from_dict({})), "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]")
        self.assertEqual(sc.home_net(sc.from_dict({"asset_nets": ["10.0.0.0/8", "fd00::/8"]})),
                         "[10.0.0.0/8,fd00::/8]")

    def test_example_file_loads(self):
        if not HAVE_YAML:
            self.skipTest("PyYAML 없음")
        path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "sensor.example.yaml")
        cfg = sc.load(path)
        self.assertFalse(cfg["suricata"]["enabled"])  # 출시 기본값 off


class TestRender(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = os.path.join(self.tmp, "base.yaml")
        with open(self.base, "w") as f:
            f.write(BASE_YAML)
        self.out = os.path.join(self.tmp, "out")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def read(self, *p):
        with open(os.path.join(self.out, *p), encoding="utf-8") as f:
            return f.read()

    def test_off(self):
        # 이전 실행에서 남은 Suricata 설정은 지운다.
        os.makedirs(os.path.join(self.out, "suricata"))
        open(os.path.join(self.out, "suricata", "suricata.yaml"), "w").close()
        cfg = sc.from_dict({"asset_nets": ["10.0.0.0/8"]})
        rc.render(cfg, self.out, base_path=None)
        self.assertFalse(os.path.exists(os.path.join(self.out, "suricata", "suricata.yaml")))
        z = self.read("zeek", "nsm_sensor.zeek")
        self.assertIn("redef AssetID::asset_nets = { 10.0.0.0/8 };", z)
        self.assertNotIn("community-id", z)  # off이면 conn.log를 지금과 같게
        st = json.loads(self.read("transport", "streams.json"))
        self.assertFalse(st["streams"]["suricata_alert"])

    def test_on_requires_base(self):
        with self.assertRaises(sc.ConfigError):
            rc.render(sc.from_dict({"suricata": {"enabled": True}}), self.out)

    def test_on_generates_full_config(self):
        if not HAVE_YAML:
            self.skipTest("PyYAML 없음")
        cfg = sc.from_dict({"suricata": {"enabled": True}, "asset_nets": ["10.0.0.0/8"], "interfaces": ["eth1"]})
        rc.render(cfg, self.out, self.base, "/rules", "/cfg/threshold.config")
        text = self.read("suricata", "suricata.yaml")
        self.assertTrue(text.startswith("%YAML 1.1\n---\n"))
        yaml_, Loader, _ = rc._suricata_yaml_io()
        y = yaml_.load(text, Loader=Loader)
        # 출력은 eve-log 하나 (fast, 기본 eve 프로토콜 로그, stats.log 제거)
        self.assertEqual([list(o)[0] for o in y["outputs"]], ["eve-log"])
        eve = y["outputs"][0]["eve-log"]
        self.assertEqual(eve["community-id"], "yes")
        types = [t if isinstance(t, str) else list(t)[0] for t in eve["types"]]
        self.assertEqual(types, ["alert", "stats"])
        alert = eve["types"][0]["alert"]
        self.assertEqual(alert["payload"], "no")
        self.assertEqual(alert["metadata"]["app-layer"], "no")
        self.assertEqual(y["vars"]["address-groups"]["HOME_NET"], "[10.0.0.0/8]")
        self.assertEqual(y["vars"]["address-groups"]["DC_SERVERS"], "$HOME_NET")  # 나머지는 그대로
        self.assertEqual(y["rule-files"], ["suricata.rules", "local.rules"])
        self.assertEqual(y["af-packet"], [{"interface": "eth1", "cluster-id": "98",
                                           "cluster-type": "cluster_flow", "defrag": "yes", "threads": "2"}])
        self.assertEqual(y["stats"]["interval"], "60")
        # 배포본 표기 보존: yes/no는 그대로, 빈 값은 'key:' 그대로 (null 문자열로 바꾸지 않음)
        self.assertIn("enabled: no", text)          # app-layer.protocols.dnp3
        self.assertIn("exception-policy:\n", text)
        self.assertNotIn("null", text)
        self.assertNotIn("true", text)
        self.assertIn("@load policy/protocols/conn/community-id-logging", self.read("zeek", "nsm_sensor.zeek"))

    def test_on_optional_outputs(self):
        if not HAVE_YAML:
            self.skipTest("PyYAML 없음")
        cfg = sc.from_dict({"suricata": {"enabled": True,
                                         "outputs": {"protocol_logs": True, "anomaly": True, "stats": False},
                                         "alert_fields": {"payload": True, "app_layer": True},
                                         "rules": {"threshold": False}}})
        rc.render(cfg, self.out, self.base, "/rules", "/cfg/threshold.config")
        yaml_, Loader, _ = rc._suricata_yaml_io()
        y = yaml_.load(self.read("suricata", "suricata.yaml"), Loader=Loader)
        types = [t if isinstance(t, str) else list(t)[0] for t in y["outputs"][0]["eve-log"]["types"]]
        self.assertEqual(types, ["alert", "anomaly"] + sc.PROTOCOL_LOG_TYPES)
        alert = y["outputs"][0]["eve-log"]["types"][0]["alert"]
        self.assertEqual((alert["payload"], alert["metadata"]["app-layer"]), ("yes", "yes"))
        self.assertEqual(y["stats"]["enabled"], "no")
        self.assertNotIn("threshold-file", y)

    def test_cli_switch_override(self):
        if not HAVE_YAML:
            self.skipTest("PyYAML 없음")
        cfgp = os.path.join(self.tmp, "sensor.json")
        with open(cfgp, "w") as f:
            json.dump({"suricata": {"enabled": True}}, f)
        rc_ = rc.main(["-c", cfgp, "-o", self.out, "--suricata", "off"])
        self.assertEqual(rc_, 0)
        self.assertFalse(os.path.exists(os.path.join(self.out, "suricata", "suricata.yaml")))
        self.assertEqual(rc.main(["-c", cfgp, "-o", self.out]), 2)  # on인데 --base 없음 -> 설정 오류


if __name__ == "__main__":
    unittest.main()
