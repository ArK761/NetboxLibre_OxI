from __future__ import annotations

from difflib import HtmlDiff, SequenceMatcher
from html import escape

try:
    from hier_config import HConfig, Platform
except ImportError:  # pragma: no cover
    HConfig = None
    Platform = None


PLATFORM_ALIASES = {
    "cisco ios": "CISCO_IOS",
    "ios": "CISCO_IOS",
    "cisco ios xr": "CISCO_XR",
    "ios xr": "CISCO_XR",
    "cisco nx-os": "CISCO_NXOS",
    "nx-os": "CISCO_NXOS",
    "nxos": "CISCO_NXOS",
    "arista eos": "ARISTA_EOS",
    "eos": "ARISTA_EOS",
    "fortinet fortios": "FORTINET_FORTIOS",
    "fortios": "FORTINET_FORTIOS",
    "hp procurve": "HP_PROCURVE",
    "aruba aoss": "HP_PROCURVE",
    "procurve": "HP_PROCURVE",
    "hp comware5": "HP_COMWARE5",
    "h3c": "HP_COMWARE5",
    "huawei vrp": "HUAWEI_VRP",
    "huawei": "HUAWEI_VRP",
    "aruba aos-cx": "ARUBA_AOSCX",
    "aos-cx": "ARUBA_AOSCX",
    "juniper junos": "JUNIPER_JUNOS",
    "junos": "JUNIPER_JUNOS",
    "nokia srl": "NOKIA_SRL",
    "vyos": "VYOS",
}


def _device_platform_name(device) -> str:
    platform = getattr(device, "platform", None)
    if not platform:
        return ""
    return str(getattr(platform, "slug", "") or getattr(platform, "name", "") or "").strip().lower()


def _hier_platform(device):
    if HConfig is None or Platform is None:
        return None, ""
    raw = _device_platform_name(device)
    key = PLATFORM_ALIASES.get(raw)
    if key is None:
        for alias, value in PLATFORM_ALIASES.items():
            if alias in raw:
                key = value
                break
    if key is None:
        return None, raw
    return getattr(Platform, key, None), raw


def _render_semantic_lines(old_lines, new_lines):
    matcher = SequenceMatcher(None, old_lines, new_lines)
    rows = []
    added = removed = changed = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for line in old_lines[i1:i2]:
                rows.append(("context", line))
        elif tag == "delete":
            removed += i2 - i1
            for line in old_lines[i1:i2]:
                rows.append(("removed", line))
        elif tag == "insert":
            added += j2 - j1
            for line in new_lines[j1:j2]:
                rows.append(("added", line))
        else:
            removed += i2 - i1
            added += j2 - j1
            changed += 1
            for line in old_lines[i1:i2]:
                rows.append(("removed", line))
            for line in new_lines[j1:j2]:
                rows.append(("added", line))

    html = [
        '<table class="table table-sm mb-0 libreoxi-semantic-diff">',
        "<thead><tr><th>Change</th><th>Configuration</th></tr></thead><tbody>",
    ]
    for kind, line in rows:
        prefix = {"added": "+", "removed": "-", "context": ""}[kind]
        css = {"added": "diff-add", "removed": "diff-remove", "context": "diff-context"}[kind]
        html.append(
            f'<tr class="{css}"><td class="diff-marker">{prefix}</td>'
            f'<td><code>{escape(line)}</code></td></tr>'
        )
    html.append("</tbody></table>")
    return "".join(html), added, removed, changed


def compare_configs(device, old_content: str, new_content: str):
    platform, platform_name = _hier_platform(device)
    fallback_reason = ""

    if platform is not None:
        try:
            old_config = HConfig.from_text(platform, old_content)
            new_config = HConfig.from_text(platform, new_content)
            old_only = old_config.difference(new_config)
            new_only = new_config.difference(old_config)
            old_lines = tuple(old_only.dump_simple())
            new_lines = tuple(new_only.dump_simple())
            html, added, removed, changed = _render_semantic_lines(old_lines, new_lines)
            return {
                "engine": "hier_config",
                "platform": platform_name,
                "semantic": True,
                "added": added,
                "removed": removed,
                "changed": changed,
                "diff_html": html,
            }
        except Exception as exc:
            fallback_reason = f"{type(exc).__name__}: {exc}"

    old_lines = old_content.splitlines()
    new_lines = new_content.splitlines()
    matcher = SequenceMatcher(None, old_lines, new_lines)
    added = removed = changed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "insert":
            added += j2 - j1
        elif tag == "delete":
            removed += i2 - i1
        elif tag == "replace":
            removed += i2 - i1
            added += j2 - j1
            changed += 1

    html_diff = HtmlDiff(tabsize=4, wrapcolumn=140).make_table(
        old_lines,
        new_lines,
        fromdesc="Older configuration",
        todesc="Newer configuration",
        context=False,
        numlines=3,
    )
    return {
        "engine": "difflib",
        "platform": platform_name,
        "semantic": False,
        "added": added,
        "removed": removed,
        "changed": changed,
        "diff_html": html_diff,
        "fallback_reason": fallback_reason,
    }
