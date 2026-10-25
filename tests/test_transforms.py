import gzip
import json
import re

from content_proxy.policy import JsonRule, Matcher
from content_proxy.transforms import decode_body, inject_cosmetic_style, prune_json


def rule(**fields):
    return JsonRule(
        Matcher("test", ("example.com",), re.compile(".*")),
        tuple(fields.get("keys", [])),
        tuple(fields.get("markers", [])),
        tuple(fields.get("conditions", [])),
    )


def test_json_keeps_organic_content_and_media_metadata():
    source = {
        "adPlacements": [1],
        "playerAds": [2],
        "streamingData": {"formats": ["keep"]},
        "items": [{"videoRenderer": {"id": "organic"}}, {"adSlotRenderer": {"id": "ad"}}],
        "nested": {"adSlots": []},
    }
    text, count = prune_json(
        json.dumps(source),
        [rule(keys=["adPlacements", "playerAds", "adSlots"], markers=["adSlotRenderer"])],
    )
    result = json.loads(text)
    assert count == 4
    assert result["streamingData"] == source["streamingData"]
    assert result["items"] == [{"videoRenderer": {"id": "organic"}}]


def test_sponsored_condition_is_explicit_and_type_strict():
    source = [
        {"node": {"is_sponsored": True}},
        {"node": {"is_sponsored": False}},
        {"node": {"is_sponsored": 1}},
        {"node": {"text": "organic"}},
    ]
    text, count = prune_json(
        json.dumps(source), [rule(conditions=[{"path": ["node", "is_sponsored"], "equals": True}])]
    )
    assert count == 1 and json.loads(text) == source[1:]


def test_unchanged_json_is_byte_preserved():
    source = '{ "regular": 123 }\n'
    assert prune_json(source, [rule(keys=["ads"])]) == (source, 0)


def test_gzip_is_decoded_with_expansion_limit():
    assert decode_body(gzip.compress(b'{"ok":true}'), "gzip", 1024) == b'{"ok":true}'
    assert decode_body(gzip.compress(b"x" * 100_000), "gzip", 1024) is None
    assert decode_body(b"not-gzip", "gzip", 1024) is None
    assert decode_body(b"data", "br", 1024) is None


def test_html_style_and_meta_csp():
    source = '<html><head><title>Test</title></head><body><div class="ad">ad</div></body></html>'
    result, changed = inject_cosmetic_style(source, [".ad"])
    assert changed and ".ad{display:none!important}" in result
    assert inject_cosmetic_style(result, [".ad"]) == (result, False)
    csp = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src none"></head></html>'
    assert inject_cosmetic_style(csp, [".ad"]) == (csp, False)
