"""Configuration change audit: severity classification, audit log and daily e-mail."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from html import escape
from pathlib import Path

from .config_changes import Change
from .i18n import MESSAGES, language_of, tr


SEVERITY_KEYS = ("low", "medium", "high", "critical")
SEVERITY_RANK = {key: rank for rank, key in enumerate(SEVERITY_KEYS)}

AUDIT_CATEGORIES = (
    ("inventory", "medium"),
    ("firewall", "critical"),
    ("access", "critical"),
    ("management", "high"),
    ("routing", "high"),
    ("vlan", "medium"),
    ("port", "medium"),
    ("description", "low"),
    ("other", "low"),
)
DEFAULT_SEVERITY = dict(AUDIT_CATEGORIES)

# The audit describes changes in plain language; configuration lines are only shown on the compare page.
AUDIT_FIELD_KEYS = ("time", "ip", "severity", "category", "change")
DEFAULT_AUDIT_FIELDS = ["time", "ip", "severity", "category", "change"]


def severities(lang: str = "en") -> list[tuple[str, str]]:
    return [(key, tr(f"severity.{key}", lang)) for key in SEVERITY_KEYS]


def severity_label(key: str, lang: str = "en") -> str:
    return tr(f"severity.{key}", lang)


def category_label(key: str, lang: str = "en", short: bool = True) -> str:
    return tr(f"category_short.{key}" if short else f"category.{key}", lang)


def audit_fields(lang: str = "en") -> list[tuple[str, str]]:
    return [(key, tr(f"field.{key}", lang)) for key in AUDIT_FIELD_KEYS]


def frequencies(lang: str = "en") -> list[tuple[str, str]]:
    return [(key, tr(f"frequency.{key}", lang)) for key in ("daily", "weekly", "monthly")]


def weekdays(lang: str = "en") -> list[tuple[int, str]]:
    return [(day, tr(f"weekday.{day}", lang)) for day in range(7)]


def smtp_securities(lang: str = "en") -> list[tuple[str, str]]:
    return [(key, tr(f"security.{key}", lang)) for key in ("none", "ssl", "starttls")]


AUDIT_FILE = "audit.jsonl"
LAST_SENT_FILE = ".audit_last_sent"

_FIREWALL = re.compile(
    r"(access-list|access-group|\bacl\b|firewall|\bnat\b|policy-options|security-polic|"
    r"config firewall|/ip firewall|/ipv6 firewall|traffic-filter|packet-filter|\bfilter\b)",
    re.IGNORECASE,
)
_ACCESS = re.compile(
    r"(^|\s|/)(username|user\s|users\b|local-user|aaa|radius|tacacs|password|secret|"
    r"enable secret|login|/user|config system admin|admin-password|dot1x|802\.1x|authentication)",
    re.IGNORECASE,
)
_MANAGEMENT = re.compile(
    r"(snmp|management vlan|ip http|https|ip ssh|\bssh\b|telnet|logging|syslog|\bntp\b|sntp|"
    r"/ip service|/system ntp|/system logging|web-server|mgmt|management|webgui|timeservers)",
    re.IGNORECASE,
)
_ROUTING = re.compile(
    r"(ip route|ipv6 route|default-gateway|default gateway|router\s|\bospf\b|\bbgp\b|\brip\b|"
    r"/ip route|static-route|routing-options|protocols)",
    re.IGNORECASE,
)
_DESCRIPTION = re.compile(
    r"(: (description|name|alias|hostname|location|contact) (changed|added|removed)|^Hostname changed)",
    re.IGNORECASE,
)


_SECRET = re.compile(
    r"(?P<key>\b(?:password|passwd|secret|community|key-string|pre-shared-key|psk|passphrase|"
    r"auth-key|priv-key|authentication-key|md5|sha|wpa2?-pre-shared-key)\b"
    r"(?:\s+(?:encrypted|cipher|hash|sha256|sha512|\d))?\s*[=\s]\s*)(?!changed\b|added\b|removed\b)(?P<value>\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)


_SECRET_CHANGE = re.compile(
    r"(?P<key>\b[\w-]*(?:password|passwd|secret|community|key|psk|passphrase|hash)[\w-]*\s+changed)\s+\"[^\"]*\"\s*->\s*\"[^\"]*\"",
    re.IGNORECASE,
)


def mask_secrets(text: str) -> str:
    """Hide passwords, secrets, SNMP communities and keys from audit output."""
    text = _SECRET_CHANGE.sub(lambda match: match.group("key"), text or "")
    return _SECRET.sub(lambda match: f"{match.group('key')}*****", text)


# Parser labels (and raw XML tags) normalised to the English label used as translation key.
LABEL_ALIASES = {
    "bcrypt-hash": "password",
    "sha512-hash": "password",
    "md5-hash": "password",
    "password": "password",
    "ipaddr": "IP address",
    "ipaddrv6": "IPv6 address",
    "subnet": "subnet mask",
    "rocommunity": "SNMP community",
    "rwcommunity": "SNMP community",
    "syslocation": "SNMP location",
    "power inline priority": "PoE priority",
    "power inline": "PoE",
}


def _label(label: str, lang: str) -> str:
    label = LABEL_ALIASES.get(label, label)
    translated = tr(f"label.{label}", lang)
    return label if translated == f"label.{label}" else translated


def _details(details: str, lang: str) -> str:
    """"name tech, description Technician" -> "name: tech, description: Technician" (translated labels)."""
    known = sorted((key[len("label."):] for key in MESSAGES if key.startswith("label.")), key=len, reverse=True)
    parts = []
    for part in re.split(r",\s+(?=[A-Za-z])", details):
        for english in known:
            if part.startswith(english + " "):
                part = f"{_label(english, lang)}: {part[len(english) + 1:]}"
                break
        parts.append(part)
    return ", ".join(parts)


def _object_name(obj: str, lang: str) -> str:
    """Parser object names -> names for the audit in the chosen language."""
    if obj in ("Global configuration", ""):
        return tr("obj.device", lang)
    obj = re.sub(r" \(interface\)$", "", obj)
    # Firewall interfaces (pfSense wan/lan/optN) are "interfaces", switch interfaces are "ports".
    obj = re.sub(r"^Interface (?!(?:wan|lan|opt\d+)\b)", "Port ", obj)
    obj = re.sub(r"^Interface ((?:wan|lan|opt\d+)\b)", lambda m: f"{tr('obj.interface', lang)} {m.group(1)}", obj)
    obj = re.sub(r'^Firewall > rule ("[^"]*"|\S+)', lambda m: f"{tr('obj.firewall_rule', lang)} {m.group(1)}", obj)
    obj = re.sub(r"^Firewall alias ", lambda m: f"{tr('obj.firewall_alias', lang)} ", obj)
    obj = re.sub(r"^User ", lambda m: f"{tr('obj.user', lang)} ", obj)
    obj = re.sub(r"^Group ", lambda m: f"{tr('obj.group', lang)} ", obj)
    obj = re.sub(r"^system > ", lambda m: f"{tr('obj.system', lang)} > ", obj)
    obj = re.sub(r"^snmpd\b", "SNMP", obj)
    return obj.replace(" > destination", f" > {tr('obj.destination', lang)}").replace(" > source", f" > {tr('obj.source', lang)}")


def _list(value: str) -> str:
    return ", ".join(part for part in re.split(r"\s*,\s*", value.strip()) if part)


def _vlan_details(details: str, lang: str) -> tuple[str, str]:
    """MikroTik details "bridge bridge1, tagged a,b, comment "x"" -> readable sentence part."""
    items = dict(re.findall(r'(name|bridge|interface|tagged|untagged|comment)\s+("[^"]*"|[^\s,]+(?:,[^\s,]+)*)', details))
    parts = []
    label = items.get("comment") or items.get("name")
    if items.get("bridge") or items.get("interface"):
        parts.append(tr("where.on", lang, name=items.get("bridge") or items.get("interface")))
    if items.get("tagged"):
        parts.append(tr("where.tagged", lang, ports=_list(items["tagged"])))
    if items.get("untagged"):
        parts.append(tr("where.untagged", lang, ports=_list(items["untagged"])))
    return (f" {label}" if label else ""), ", ".join(parts)


def _paren(text: str) -> str:
    return f" ({text})" if text else ""


_PART = re.compile(
    r'^(?P<label>[\w.\-]+) (?:(?P<set>set to) "(?P<value>.*)"|(?P<unset>unset)|changed "(?P<old>.*)" -> "(?P<new>.*)"|(?P<secret>changed))$'
)


def _value_parts(message: str, lang: str):
    """"/system logging [0]: action set to "remote"; disabled unset" -> (object, [translated parts])."""
    match = re.match(r"^(.+?): (.+)$", message)
    if not match or not re.search(r' set to "| unset|; |^disabled changed "', match.group(2)):
        return None
    translated = []
    for part in match.group(2).split("; "):
        item = _PART.match(part)
        if not item:
            return None
        label = _label(item.group("label"), lang)
        state = item.group("value") if item.group("set") else item.group("new")
        if item.group("label") == "disabled" and state in ("yes", "no", "true", "false"):
            translated.append(tr("part.entry_disabled" if state in ("yes", "true") else "part.entry_enabled", lang))
            continue
        if item.group("set"):
            translated.append(tr("part.set", lang, label=label, value=item.group("value")))
        elif item.group("unset"):
            translated.append(tr("part.unset", lang, label=label))
        elif item.group("secret"):
            translated.append(tr("part.changed_secret", lang, label=label))
        else:
            translated.append(tr("part.changed", lang, label=label, old=item.group("old"), new=item.group("new")))
    return match.group(1), translated


def audit_text(change: dict, lang: str = "en") -> str:
    """Plain-language description of a change for the audit (no configuration lines)."""
    message = change.get("message", "")

    if message == "@new_device":
        details = ", ".join(
            part
            for part in (change.get("model", ""), tr("chg.platform", lang, name=change["platform"]) if change.get("platform") else "")
            if part
        )
        return tr("chg.new_device", lang, model=_paren(details))

    # MikroTik bridge VLAN entry
    match = re.match(r"^VLAN (\S+) (added|removed) \((.*)\)$", message)
    if match and re.search(r"\b(bridge|tagged|untagged|interface) ", match.group(3)):
        label, where = _vlan_details(match.group(3), lang)
        return tr(f"chg.vlan_{match.group(2)}", lang, vlan=match.group(1), label=label, details=_paren(where))

    match = re.match(r"^VLAN (.+?)(?: \(interface\))? (added|removed)(?: \((.*)\))?$", message)
    if match:
        details = _paren(_details(match.group(3), lang)) if match.group(3) else ""
        return tr(f"chg.vlan_{match.group(2)}", lang, vlan=match.group(1), label="", details=details)

    match = re.match(r"^Interface (.+?) (added|removed)(?: \((.*)\))?$", message)
    if match:
        details = _paren(_details(match.group(3), lang)) if match.group(3) else ""
        return tr(f"chg.port_{match.group(2)}", lang, obj=_object_name("Interface " + match.group(1), lang), details=details)

    match = re.match(r"^VLAN list changed .*\((.*)\)$", message)
    if match:
        sentences = [
            tr(f"chg.vlan_db_{action}", lang, vlan=vlans)
            for action, vlans in re.findall(r"(added|removed) ([\d,\-]+)", match.group(1))
        ]
        return "; ".join(sentences) + "."

    match = re.match(r'^VLAN (\S+): (tagged|untagged) changed "(.*)" -> "(.*)"$', message)
    if match:
        old_ports = {port for port in match.group(3).split(",") if port}
        new_ports = {port for port in match.group(4).split(",") if port}
        mode = tr(f"mode.{match.group(2)}", lang)
        sentences = []
        for ports, key in ((sorted(new_ports - old_ports), "to_vlan"), (sorted(old_ports - new_ports), "from_vlan")):
            if ports:
                prefix = "chg.port_" if len(ports) == 1 else "chg.ports_"
                sentences.append(tr(prefix + key, lang, ports=", ".join(ports), vlan=match.group(1), mode=mode))
        if sentences:
            return "; ".join(sentences) + "."

    match = re.match(r"^/user name=(\S+): (.+) changed$", message)
    if match:
        obj = f"{tr('obj.user', lang)} {match.group(1)}"
        if LABEL_ALIASES.get(match.group(2), match.group(2)) == "password":
            return tr("chg.password_changed", lang, obj=obj)
        return tr("chg.item_changed", lang, obj=obj, label=_label(match.group(2), lang))

    match = re.match(r"^(.+?): (snmp-server community|snmp-agent community|rocommunity|rwcommunity) changed$", message)
    if match:
        return tr("chg.snmp_community", lang)

    match = re.match(r'^(/ip firewall \S+|/ipv6 firewall \S+): line (added|removed) "(?:add )?(.*)"$', message)
    if match:
        return tr(f"chg.fw_rule_{match.group(2)}", lang, section=match.group(1), rule=match.group(3))

    match = re.match(r"^(.+?): (tagged|untagged|allowed|member) VLANs changed .*\((.*)\)$", message)
    if match:
        port = _object_name(match.group(1), lang)
        mode = tr(f"mode.{match.group(2)}", lang)
        sentences = [
            tr(f"chg.vlan_on_port_{action}", lang, vlan=vlans, port=port, mode=mode)
            for action, vlans in re.findall(r"(added|removed) ([\d,\-]+)", match.group(3))
        ]
        return "; ".join(sentences) + "."

    match = re.match(r'^Hostname changed "(.*)" -> "(.*)"$', message)
    if match:
        return tr("chg.renamed", lang, old=match.group(1), new=match.group(2))

    match = re.match(r"^(User|Group) (\S+) (added|removed)(?: \((.*)\))?$", message)
    if match:
        kind = "user" if match.group(1) == "User" else "group"
        return tr(f"chg.{kind}_{match.group(3)}", lang, name=match.group(2))

    match = re.match(r"^User (\S+) changed", message)
    if match:
        return tr("chg.user_modified", lang, name=match.group(1))

    parts = _value_parts(message, lang)
    if parts:
        return tr("chg.parts", lang, obj=_object_name(parts[0], lang), parts="; ".join(parts[1]))

    match = re.match(r'^(/\S.*?): line (added|removed) "add (.*)"$', message)
    if match:
        return tr(f"chg.entry_{match.group(2)}", lang, obj=match.group(1), values=match.group(3))

    match = re.match(r'^(.+?): (.+?) changed "(.*)" -> "(.*)"(.*)$', message)
    if match:
        return tr(
            "chg.value_changed", lang,
            obj=_object_name(match.group(1), lang), label=_label(match.group(2), lang), old=match.group(3), new=match.group(4),
        )

    match = re.match(r"^(.+?): administratively (enabled|disabled)", message)
    if match:
        return tr(f"chg.{match.group(2)}", lang, obj=_object_name(match.group(1), lang))

    match = re.match(r'^(.+?): line (added|removed) "(.*)"$', message)
    if match:
        return tr(f"chg.line_{match.group(2)}", lang, obj=_object_name(match.group(1), lang), line=match.group(3))

    match = re.match(r'^(.+?): (.+?) (added|removed) "(.*)"$', message)
    if match:
        return tr(
            f"chg.value_{match.group(3)}", lang,
            obj=_object_name(match.group(1), lang), label=_label(match.group(2), lang), value=match.group(4),
        )

    match = re.match(r"^(.+?): (.+) changed$", message)
    if match:
        obj = _object_name(match.group(1), lang)
        if LABEL_ALIASES.get(match.group(2), match.group(2)) == "password":
            return tr("chg.password_changed", lang, obj=obj)
        return tr("chg.item_changed", lang, obj=obj, label=_label(match.group(2), lang))

    match = re.match(r'^Firewall > rule ("[^"]*"|\S+) (added|removed)(?: \((.*)\))?$', message)
    if match:
        details = re.sub(r",?\s*description [^,]*$", "", match.group(3) or "")
        return tr(
            f"chg.rule_{match.group(2)}", lang,
            obj=tr("obj.firewall_rule", lang), rule=match.group(1), details=_paren(_details(details, lang)) if details else "",
        )

    match = re.match(r"^(.+?) (added|removed)(?: \((.*)\))?$", message)
    if match:
        raw = match.group(3) or ""
        if match.group(1).startswith("/"):
            raw = re.sub(r"(^|; )add ", r"\1", raw)
        details = _paren(_details(raw, lang)) if raw else ""
        return tr(f"chg.section_{match.group(2)}", lang, obj=_object_name(match.group(1), lang), details=details)

    return message


def classify(change: Change) -> str:
    """Return the audit category key of a detected change."""
    text = " ".join((change.obj, change.message, change.old, change.new))
    if change.category == "Security" or _FIREWALL.search(text):
        return "firewall"
    if _ACCESS.search(change.old) or _ACCESS.search(change.new) or _ACCESS.search(change.obj):
        return "access"
    if _MANAGEMENT.search(text):
        return "management"
    if change.category == "Routing" or _ROUTING.search(text):
        return "routing"
    if re.search(r": (IP address|IPv6 address|ipaddr|ipaddrv6|subnet) ", change.message):
        return "routing"
    if _DESCRIPTION.search(change.message):
        return "description"
    if change.category == "VLAN" or "VLAN" in change.message:
        return "vlan"
    if "administratively" in change.message or "port security" in text.lower():
        return "port"
    if change.category == "Interface" and re.match(r"^Interface \S+ (added|removed)", change.message):
        return "port"
    return "other"


def severity_map(settings) -> dict[str, str]:
    configured = getattr(settings, "audit_severity_map", None) or {}
    return {key: configured.get(key, default) for key, default in DEFAULT_SEVERITY.items()}


def severity_of(settings, category: str) -> str:
    return severity_map(settings).get(category, "low")


def annotate(settings, changes: list[Change]) -> list[dict]:
    """Return changes as dictionaries with audit category and severity."""
    lang = language_of(settings)
    rows = []
    for change in changes:
        category = classify(change)
        severity = severity_of(settings, category)
        rows.append(
            {
                "action": change.action,
                "type": change.category,
                "category": category,
                "category_label": category_label(category, lang),
                "severity": severity,
                "severity_label": severity_label(severity, lang),
                "object": change.obj,
                "message": mask_secrets(change.message),
                "old": mask_secrets(change.old),
                "new": mask_secrets(change.new),
            }
        )
        rows[-1]["text"] = audit_text(rows[-1], lang)
    return rows


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------

def _root(settings) -> Path:
    return Path(settings.storage_root).expanduser().resolve()


def record(settings, device, ip: str | None, changes: list[Change], author: str = "") -> None:
    """Append the detected changes of one device to the audit log."""
    if not changes:
        return
    entry = {
        "time": datetime.now(dt_timezone.utc).isoformat(timespec="seconds"),
        "device_id": device.pk,
        "device": str(device),
        "ip": ip or "",
        "author": author or "",
        "changes": [
            {
                "category": classify(change),
                "action": change.action,
                "object": change.obj,
                "message": mask_secrets(change.message),
                "old": mask_secrets(change.old),
                "new": mask_secrets(change.new),
            }
            for change in changes
        ],
    }
    root = _root(settings)
    root.mkdir(parents=True, exist_ok=True)
    with (root / AUDIT_FILE).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_entries(settings, since: datetime, until: datetime) -> list[dict]:
    path = _root(settings) / AUDIT_FILE
    if not path.exists():
        return []
    entries = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
                when = datetime.fromisoformat(entry["time"])
            except (ValueError, KeyError, TypeError):
                continue
            if since <= when < until:
                entry["when"] = when
                entries.append(entry)
    return entries


# --------------------------------------------------------------------------
# Daily report
# --------------------------------------------------------------------------

def _report_from_entries(settings, entries: list[dict], since: datetime, until: datetime) -> dict:
    """Group audit entries by device, filtered by the configured minimum severity."""
    minimum = SEVERITY_RANK.get(getattr(settings, "audit_min_severity", "low") or "low", 0)
    severities = severity_map(settings)
    devices: dict[str, dict] = {}
    lang = language_of(settings)
    counts = {key: 0 for key in SEVERITY_KEYS}
    skipped = 0

    for entry in entries:
        for change in entry.get("changes", []):
            category = change.get("category") or "other"
            severity = severities.get(category, "low")
            if SEVERITY_RANK[severity] < minimum:
                skipped += 1
                continue
            counts[severity] += 1
            device = devices.setdefault(
                entry.get("device", "?"),
                {"name": entry.get("device", "?"), "ip": entry.get("ip", ""), "changes": [], "authors": []},
            )
            author = entry.get("author") or ""
            if author and author not in device["authors"]:
                device["authors"].append(author)
            device["changes"].append(
                {
                    **change,
                    "author": entry.get("author") or "",
                    "when": entry["when"],
                    "severity": severity,
                    "severity_label": severity_label(severity, lang),
                    "category_label": category_label(category, lang),
                }
            )

    ordered = sorted(devices.values(), key=lambda device: device["name"].lower())
    for device in ordered:
        device["changes"].sort(key=lambda change: (change["when"], -SEVERITY_RANK[change["severity"]]))
    return {
        "devices": ordered,
        "counts": counts,
        "total": sum(counts.values()),
        "skipped": skipped,
        "since": since,
        "until": until,
    }


def build_report(settings, since: datetime, until: datetime) -> dict:
    return _report_from_entries(settings, read_entries(settings, since, until), since, until)


def build_preview(
    settings, device, ip: str | None, changes: list[Change], since: datetime, until: datetime, author: str = ""
) -> dict:
    """Audit report for a single comparison, as it would be sent to the security manager."""
    entry = {
        "device": str(device),
        "ip": ip or "",
        "author": author or "",
        "when": until,
        "changes": [
            {
                "category": classify(change),
                "action": change.action,
                "object": change.obj,
                "message": mask_secrets(change.message),
                "old": mask_secrets(change.old),
                "new": mask_secrets(change.new),
            }
            for change in changes
        ],
    }
    return _report_from_entries(settings, [entry], since, until)


def _format_time(value: datetime, settings) -> str:
    from django.utils import timezone

    return timezone.localtime(value).strftime(getattr(settings, "datetime_format", "%d.%m.%Y %H:%M:%S"))


SEVERITY_COLOR = {"low": "#6c757d", "medium": "#d39e00", "high": "#fd7e14", "critical": "#dc3545"}


def report_fields(settings) -> list[str]:
    fields = [field for field in (getattr(settings, "audit_fields", None) or DEFAULT_AUDIT_FIELDS) if field in AUDIT_FIELD_KEYS]
    if "change" not in fields:
        fields.append("change")
    return fields


def severity_summary(report: dict, lang: str) -> str:
    counts = report["counts"]
    return ", ".join(
        f"{tr(f'severity_plural.{key}', lang)}: {counts[key]}" for key in reversed(SEVERITY_KEYS) if counts[key]
    )


def report_period(settings, report: dict) -> str:
    if report.get("period_label"):
        return report["period_label"]
    return f"{_format_time(report['since'], settings)} - {_format_time(report['until'], settings)}"


def report_subject(settings, report: dict) -> str:
    lang = language_of(settings)
    summary = severity_summary(report, lang)
    return tr("report.subject", lang, devices=len(report["devices"]), total=report["total"]) + (f" ({summary})" if summary else "")


def render_report(settings, report: dict) -> tuple[str, str, str]:
    """Return (subject, plain text, HTML) of the audit e-mail."""
    lang = language_of(settings)
    fields = report_fields(settings)
    labels = dict(audit_fields(lang))
    period = report_period(settings, report)
    summary = severity_summary(report, lang)
    subject = report_subject(settings, report)

    def cell(change, field):
        if field == "time":
            return _format_time(change["when"], settings)
        if field == "severity":
            return change["severity_label"]
        if field == "category":
            return change["category_label"]
        if field == "change":
            return audit_text(change, lang)
        return change.get(field, "")

    title = tr("report.title", lang)
    text = [f"{title} (LibreOXI)", tr("report.period", lang, period=period), ""]
    html = [
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#212529">',
        f"<h2 style=\"margin:0 0 4px\">{escape(title)}</h2>",
        f"<p style=\"margin:0 0 16px;color:#6c757d\">{escape(tr('report.period', lang, period=period))}</p>",
    ]
    if not report["devices"]:
        text.append(tr("report.no_changes", lang))
        html.append(f"<p>{escape(tr('report.no_changes', lang))}</p>")
    else:
        changes_line = tr("report.changes", lang, total=report["total"]) + (f" ({summary})" if summary else "")
        text.extend([changes_line, ""])
        html.append(f"<p><strong>{escape(changes_line)}</strong></p>")

    columns = [field for field in fields if field != "ip"]
    for device in report["devices"]:
        device_title = device["name"] + (f" ({device['ip']})" if device["ip"] and "ip" in fields else "")
        text.append(f"== {device_title} ==")
        html.append(f"<h3 style=\"margin:20px 0 6px\">{escape(device_title)}</h3>")
        for author in device.get("authors", []):
            text.append(tr("report.saved_by", lang, author=author))
            html.append(f"<p style=\"margin:0 0 6px;color:#495057\">{escape(tr('report.saved_by', lang, author=author))}</p>")
        html.append('<table style="border-collapse:collapse;width:100%" cellpadding="6">')
        html.append(
            "<tr>"
            + "".join(
                f'<th style="text-align:left;border-bottom:2px solid #dee2e6;background:#f8f9fa">{escape(labels[field])}</th>'
                for field in columns
            )
            + "</tr>"
        )
        for change in device["changes"]:
            text.append(
                " | ".join(
                    f"{labels[field]}: {cell(change, field)}" if field in ("old", "new") else str(cell(change, field))
                    for field in columns
                    if cell(change, field) or field not in ("old", "new")
                )
            )
            row = []
            for field in columns:
                value = escape(str(cell(change, field)))
                if field == "severity":
                    value = (
                        f'<span style="color:#fff;background:{SEVERITY_COLOR[change["severity"]]};'
                        f'padding:2px 6px;border-radius:4px">{value}</span>'
                    )
                elif field in ("old", "new") and value:
                    value = f'<code style="font-size:12px">{value}</code>'
                row.append(f'<td style="border-bottom:1px solid #dee2e6;vertical-align:top">{value}</td>')
            html.append("<tr>" + "".join(row) + "</tr>")
        html.append("</table>")
        text.append("")

    html.append("</div>")
    return subject, "\n".join(text), "".join(html)


def recipients(settings) -> list[str]:
    raw = getattr(settings, "audit_email_recipients", "") or ""
    return [address.strip() for address in re.split(r"[,;\s]+", raw) if address.strip()]


def from_address(settings) -> str:
    from email.utils import formataddr

    from django.conf import settings as django_settings

    address = (
        (getattr(settings, "smtp_from", "") or "").strip()
        or getattr(django_settings, "DEFAULT_FROM_EMAIL", "")
        or getattr(django_settings, "SERVER_EMAIL", "")
    )
    name = (getattr(settings, "smtp_from_name", "") or "").strip()
    return formataddr((name, address)) if name and address and "<" not in address else address


def _deliver(settings, message) -> None:
    """Send a Django EmailMessage.

    With an SMTP server configured in the plugin the message is sent directly with
    smtplib (independent of NetBox's own e-mail configuration, which may use Django
    MAILERS); without it, NetBox's default e-mail configuration is used.
    """
    import smtplib
    import ssl
    from email.utils import parseaddr

    host = (getattr(settings, "smtp_host", "") or "").strip()
    if not host:
        message.send(fail_silently=False)
        return

    security = getattr(settings, "smtp_security", "none") or "none"
    port = getattr(settings, "smtp_port", 0) or (465 if security == "ssl" else 587 if security == "starttls" else 25)
    timeout = getattr(settings, "smtp_timeout", 10) or 10
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if security == "starttls" or (
            security == "none" and getattr(settings, "smtp_auto_tls", False) and server.has_extn("starttls")
        ):
            server.starttls(context=context)
            server.ehlo()
        if getattr(settings, "smtp_auth", False) and getattr(settings, "smtp_username", ""):
            server.login(settings.smtp_username, getattr(settings, "smtp_password", "") or "")
        envelope_from = parseaddr(message.from_email)[1] or message.from_email
        # send_message() accepts both the legacy and the modern (Django 6) message classes.
        server.send_message(message.message(), from_addr=envelope_from, to_addrs=message.recipients())
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            server.close()


def send_test_email(settings, to: list[str] | None = None) -> None:
    from django.core.mail import EmailMessage
    from django.utils import timezone

    lang = language_of(settings)
    to = to or recipients(settings)
    if not to:
        raise ValueError(tr("mail.no_recipients", lang))
    now = timezone.localtime().strftime(getattr(settings, "datetime_format", "%d.%m.%Y %H:%M:%S"))
    server = (getattr(settings, "smtp_host", "") or "").strip() or tr("mail.netbox_settings", lang)
    body = tr("mail.test_body", lang, time=now, server=server, recipients=", ".join(to))
    message = EmailMessage(subject=tr("mail.test_subject", lang), body=body, from_email=from_address(settings), to=to)
    _deliver(settings, message)


def build_audit(settings, devices, since, until, label: str) -> dict:
    from django.utils import timezone

    entries = collect_entries(settings, devices, since, until)
    report = _report_from_entries(
        settings, entries, since or datetime(1970, 1, 1, tzinfo=dt_timezone.utc), until or timezone.now()
    )
    report["period_label"] = label
    return report


def html_document(settings, report: dict) -> str:
    subject, _text, html = render_report(settings, report)
    return (
        f'<!doctype html><html lang="{language_of(settings)}"><head><meta charset="utf-8">'
        f"<title>{escape(subject)}</title></head><body style=\"background:#fff;margin:24px\">{html}</body></html>"
    )


def send_audit(
    settings, devices, since, until, label: str, force: bool = False, to: list[str] | None = None,
    attachments: list[str] | None = None,
) -> dict:
    """Build the audit for the period and e-mail it. Returns {"sent", "total", "reason"}.

    attachments: list of "pdf", "csv", "html"; None = use the saved e-mail settings.
    """
    from django.core.mail import EmailMultiAlternatives
    from django.utils import timezone

    lang = language_of(settings)
    to = to or recipients(settings)
    if not to:
        return {"sent": False, "total": 0, "reason": tr("mail.no_recipients", lang), "reason_en": tr("mail.no_recipients", "en")}
    report = build_audit(settings, devices, since, until, label)
    if not report["total"] and not force and not getattr(settings, "audit_send_empty", False):
        return {"sent": False, "total": 0, "reason": tr("mail.no_changes", lang), "reason_en": tr("mail.no_changes", "en")}

    if attachments is None:
        attachments = [
            kind
            for kind, enabled in (
                ("pdf", getattr(settings, "audit_email_attach_pdf", True)),
                ("csv", getattr(settings, "audit_email_attach_csv", False)),
            )
            if enabled
        ]
    subject, text, html = render_report(settings, report)
    message = EmailMultiAlternatives(subject=subject, body=text, from_email=from_address(settings), to=to)
    message.attach_alternative(html, "text/html")
    stamp = timezone.localtime().strftime("%Y-%m-%d")
    if "pdf" in attachments:
        from .audit_pdf import build_pdf

        message.attach(f"libreoxi-audit_{stamp}.pdf", build_pdf(settings, report, subject), "application/pdf")
    if "csv" in attachments:
        message.attach(f"libreoxi-audit_{stamp}.csv", report_csv(settings, report).encode("utf-8"), "text/csv")
    if "html" in attachments:
        message.attach(f"libreoxi-audit_{stamp}.html", html_document(settings, report).encode("utf-8"), "text/html")
    _deliver(settings, message)
    return {"sent": True, "total": report["total"], "reason": ""}


def read_last_sent(settings) -> datetime | None:
    try:
        return datetime.fromisoformat((_root(settings) / LAST_SENT_FILE).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def write_last_sent(settings, when: datetime) -> None:
    try:
        (_root(settings) / LAST_SENT_FILE).write_text(when.isoformat(timespec="seconds"), encoding="ascii")
    except OSError:
        pass


def scheduled_period(settings, now: datetime):
    """Return (slot, since, until, label) when the scheduled audit e-mail is due, else None."""
    from django.utils import timezone

    try:
        hour, minute = (int(part) for part in (settings.audit_email_time or "07:00").split(":", 1))
    except ValueError:
        return None
    local_now = timezone.localtime(now)
    slot = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if local_now < slot:
        return None
    last_sent = read_last_sent(settings)
    if last_sent is not None and last_sent >= slot:
        return None

    today = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    date_format = (getattr(settings, "datetime_format", "") or "%d.%m.%Y").split(" ")[0]
    frequency = getattr(settings, "audit_email_frequency", "daily") or "daily"
    if frequency == "weekly":
        if local_now.weekday() != (getattr(settings, "audit_email_weekday", 0) or 0):
            return None
        since = timezone.make_aware(datetime.combine((today - timedelta(days=7)).date(), datetime.min.time()))
        last_day = (today - timedelta(days=1)).date()
        return slot, since, today, tr("period.week", language_of(settings), start=since.strftime(date_format), end=last_day.strftime(date_format))
    if frequency == "monthly":
        if local_now.day != 1:
            return None
        previous = (today - timedelta(days=1)).date().replace(day=1)
        since = timezone.make_aware(datetime.combine(previous, datetime.min.time()))
        return slot, since, today, tr("period.month", language_of(settings), month=previous.strftime("%m/%Y"))
    yesterday = (today - timedelta(days=1)).date()
    since = timezone.make_aware(datetime.combine(yesterday, datetime.min.time()))
    return slot, since, today, tr("period.yesterday", language_of(settings), day=yesterday.strftime(date_format))


# --------------------------------------------------------------------------
# Audit generated on demand from the stored configuration history
# --------------------------------------------------------------------------

def revision_time(name: str) -> datetime | None:
    """UTC time of a history file named "YYYY-mm-dd_HH-MM-SS.cfg"."""
    try:
        return datetime.strptime(name.removesuffix(".cfg"), "%Y-%m-%d_%H-%M-%S").replace(tzinfo=dt_timezone.utc)
    except ValueError:
        return None


def collect_entries(settings, devices, since: datetime | None, until: datetime | None) -> list[dict]:
    """Compare consecutive stored revisions of every device and return audit entries.

    A revision is reported when it was stored within [since, until) and an older
    revision exists to compare it with (the very first backup is not a change).
    """
    from .config_changes import compare, config_author
    from .storage import list_history

    entries = []
    for device in devices:
        try:
            files = [path for path in list_history(settings.storage_root, device.pk) if path.name != "current.cfg"]
        except OSError:
            continue
        revisions = sorted(
            ((revision_time(path.name), path) for path in files if revision_time(path.name) is not None),
            key=lambda item: item[0],
        )
        ip = str(device.primary_ip4.address.ip) if getattr(device, "primary_ip4", None) else ""
        first_seen = _first_seen(settings, device, revisions)
        if first_seen is not None and (since is None or first_seen >= since) and (until is None or first_seen < until):
            model, platform = _device_model(device)
            entries.append(
                {
                    "device": str(device),
                    "ip": ip,
                    "when": first_seen,
                    "author": "",
                    "changes": [
                        {
                            "category": "inventory",
                            "action": "added",
                            "object": str(device),
                            "message": "@new_device",
                            "model": model,
                            "platform": platform,
                            "old": "",
                            "new": "",
                        }
                    ],
                }
            )

        previous_content = None
        for when, path in revisions:
            in_period = (since is None or when >= since) and (until is None or when < until)
            if not in_period and (until is not None and when >= until):
                break
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if in_period and previous_content is not None:
                changes = compare(previous_content, content)
                if changes:
                    entries.append(
                        {
                            "device": str(device),
                            "ip": ip,
                            "when": when,
                            "author": config_author(content),
                            "changes": [
                                {
                                    "category": classify(change),
                                    "action": change.action,
                                    "object": change.obj,
                                    "message": mask_secrets(change.message),
                                    "old": mask_secrets(change.old),
                                    "new": mask_secrets(change.new),
                                }
                                for change in changes
                            ],
                        }
                    )
            previous_content = content
    return entries


def _device_model(device) -> tuple[str, str]:
    model = ""
    device_type = getattr(device, "device_type", None)
    if device_type is not None:
        manufacturer = getattr(device_type, "manufacturer", None)
        model = " ".join(str(part) for part in (manufacturer, getattr(device_type, "model", "")) if part)
    platform = getattr(device, "platform", None)
    return model, str(platform) if platform else ""


def _first_seen(settings, device, revisions) -> datetime | None:
    """When the device entered change monitoring (its first configuration backup)."""
    from .storage import FIRST_BACKUP_MARKER, device_dir

    try:
        marker = device_dir(settings.storage_root, device.pk, create=False) / FIRST_BACKUP_MARKER
        return datetime.fromisoformat(marker.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        pass
    if not revisions:
        return None
    # Devices backed up before the marker existed: the oldest revision is the first
    # backup only if retention cannot have deleted anything yet.
    oldest = revisions[0][0]
    retention_days = getattr(settings, "retention_days", 0) or 0
    retention_revisions = getattr(settings, "retention_revisions", 0) or 0
    now = datetime.now(dt_timezone.utc)
    if retention_revisions and len(revisions) >= retention_revisions:
        return None
    if retention_days and oldest < now - timedelta(days=retention_days - 1):
        return None
    return oldest


def report_csv(settings, report: dict) -> str:
    """Semicolon separated CSV (opens directly in Excel with Slovak locale)."""
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    lang = language_of(settings)
    writer.writerow([tr(f"field.{key}", lang) for key in ("device", "ip", "time", "severity", "category", "change", "saved_by")])
    for device in report["devices"]:
        for change in device["changes"]:
            writer.writerow(
                [
                    device["name"],
                    device["ip"],
                    _format_time(change["when"], settings),
                    change["severity_label"],
                    change["category_label"],
                    audit_text(change, lang),
                    change.get("author", ""),
                ]
            )
    return "﻿" + buffer.getvalue()
