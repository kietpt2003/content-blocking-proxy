import json

from content_proxy.addon import ContentBlocker
from content_proxy.policy import load_policy


def test_bad_reload_keeps_previous_policy_and_recovers(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nenabled: true\n")
    addon = ContentBlocker()
    addon.policy_path = path
    addon.policy = load_policy(path)
    addon.stamp = addon._stamp(path)
    path.write_text("version: [broken")
    addon.reload_policy()
    assert addon.policy.enabled and addon.last_reload_error
    path.write_text("version: 1\nenabled: false\n")
    addon.reload_policy()
    assert not addon.policy.enabled and not addon.last_reload_error
    addon.stats_path = tmp_path / "stats.json"
    addon.write_stats()
    assert json.loads(addon.stats_path.read_text())["enabled"] is False
