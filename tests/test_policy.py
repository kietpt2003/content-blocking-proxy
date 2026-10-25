from pathlib import Path

import pytest
import yaml

from content_proxy.policy import host_matches, load_policy


def policy_file(tmp_path, **fields):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"version": 1, **fields}))
    return path


def test_domain_boundary():
    assert host_matches("ads.example.com", "example.com")
    assert host_matches("EXAMPLE.COM.", "example.com")
    assert not host_matches("notexample.com", "example.com")
    assert not host_matches("example.com.attacker.test", "example.com")


def test_default_policy_is_valid():
    policy = load_policy(Path(__file__).parents[1] / "config/proxy.yaml")
    assert policy.enabled and policy.json_rules and policy.block
    assert policy.block[1].matches("www.googleadservices.com", "/pagead/aclk?x=1")


@pytest.mark.parametrize(
    "fields",
    [
        {"enabled": "false"},
        {"max_body_bytes": 99_999_999},
        {"block_rule": []},
        {"block_rules": [{"id": "broken", "domains": ["https://example.com"]}]},
        {"block_rules": [{"id": "broken", "domains": ["example.com"], "path_regex": "["}]},
        {"block_rules": [{"id": "dup", "domains": ["a.test"]}] * 2},
        {
            "html_rules": [
                {
                    "id": "unsafe",
                    "domains": ["example.com"],
                    "hide_selectors": ["</style><script>bad</script>"],
                }
            ]
        },
    ],
)
def test_invalid_policy_rejected(tmp_path, fields):
    with pytest.raises(ValueError):
        load_policy(policy_file(tmp_path, **fields))


def test_malformed_yaml_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: [broken")
    with pytest.raises(ValueError):
        load_policy(path)
