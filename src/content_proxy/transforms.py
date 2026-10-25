"""Body transformations; never evaluate upstream JavaScript or modify media bytes."""

import json
import re
import zlib

from .policy import JsonRule


def decode_body(data: bytes, encoding: str, limit: int) -> bytes | None:
    if len(data) > limit:
        return None
    if encoding in ("", "identity"):
        return data
    if encoding != "gzip":
        return None
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        result = decoder.decompress(data, limit + 1)
        if len(result) > limit or not decoder.eof or decoder.unused_data:
            return None
        return result
    except zlib.error:
        return None


def _equal_at(item: dict, path: list[str], expected) -> bool:
    value = item
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    # JSON true must not match integer 1, and missing fields never match false.
    return type(value) is type(expected) and value == expected


def prune_json(text: str, rules: list[JsonRule]) -> tuple[str, int]:
    value = json.loads(text)
    keys = {key for rule in rules for key in rule.remove_keys}
    markers = {key for rule in rules for key in rule.remove_items_with_keys}
    conditions = [c for rule in rules for c in rule.remove_items_where]
    removed = 0

    def visit(node, depth=0):
        nonlocal removed
        if depth > 128:
            raise ValueError("JSON exceeds transformation nesting limit")
        if isinstance(node, dict):
            result = {}
            for key, item in node.items():
                if key in keys:
                    removed += 1
                else:
                    result[key] = visit(item, depth + 1)
            return result
        if isinstance(node, list):
            result = []
            for item in node:
                if isinstance(item, dict) and (
                    markers.intersection(item)
                    or any(_equal_at(item, c["path"], c["equals"]) for c in conditions)
                ):
                    removed += 1
                else:
                    result.append(visit(item, depth + 1))
            return result
        return node

    cleaned = visit(value)
    return (
        (json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")), removed)
        if removed
        else (text, 0)
    )


def inject_cosmetic_style(text: str, selectors: list[str]) -> tuple[str, bool]:
    # Preserve site CSP. A meta CSP may also forbid inline style, so skip it too.
    if re.search(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?content-security-policy\b", text, re.I):
        return text, False
    head = re.search(r"<head\b[^>]*>", text, re.I)
    if not head or 'id="content-proxy-cosmetic"' in text:
        return text, False
    style = (
        '<style id="content-proxy-cosmetic">'
        + ",".join(selectors)
        + "{display:none!important}</style>"
    )
    return text[: head.end()] + style + text[head.end() :], True
