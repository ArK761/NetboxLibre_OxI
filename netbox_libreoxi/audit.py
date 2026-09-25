"""Configuration change audit: severity classification, audit log and daily e-mail."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from html import escape
from pathlib import Path

from .config_changes import Change


SEVERITIES = (
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
)
SEVERITY_RANK = {key: rank for rank, (key, _) in enumerate(SEVERITIES)}
SEVERITY_LABEL = dict(SEVERITIES)

AUDIT_CATEGORIES = (
    ("firewall", "Firewall / ACL", "critical"),
    ("access", "Users and access (users, passwords, AAA)", "critical"),
    ("management", "Device management (SNMP, SSH/HTTP, logging, NTP, management VLAN)", "high"),
    ("routing", "Routing (static routes, OSPF, BGP, gateway)", "high"),
    ("vlan", "VLANs (added/removed VLANs, port VLANs)", "medium"),
    ("port", "Ports (shutdown/no shutdown, port security)", "medium"),
    ("description", "Descriptions and names (port description, VLAN name, hostname)", "low"),
    ("other", "Other changes", "low"),
)
AUDIT_CATEGORY_LABEL = {key: label.split(" (")[0] for key, label, _ in AUDIT_CATEGORIES}
DEFAULT_SEVERITY = {key: severity for key, _, severity in AUDIT_CATEGORIES}

AUDIT_FIELDS = (
    ("time", "Time"),
    ("ip", "Device IP"),
    ("severity", "Severity"),
    ("category", "Category"),
    ("change", "Change"),
    ("old", "Older line"),
    ("new", "Newer line"),
)
DEFAULT_AUDIT_FIELDS = ["time", "ip", "severity", "category", "change", "old", "new"]

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
    r"/ip service|/system ntp|/system logging|web-server|mgmt|management)",
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
    r"(?P<key>\b[\w-]*(?:password|passwd|secret|community|key|psk|passphrase)[\w-]*\s+changed)\s+\"[^\"]*\"\s*->\s*\"[^\"]*\"",
    re.IGNORECASE,
)


def mask_secrets(text: str) -> str:
    """Hide passwords, secrets, SNMP communities and keys from audit output."""
    text = _SECRET_CHANGE.sub(lambda match: match.group("key"), text or "")
    return _SECRET.sub(lambda match: f"{match.group('key')}*****", text)


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
    rows = []
    for change in changes:
        category = classify(change)
        severity = severity_of(settings, category)
        rows.append(
            {
                "action": change.action,
                "type": change.category,
                "category": category,
                "category_label": AUDIT_CATEGORY_LABEL[category],
                "severity": severity,
                "severity_label": SEVERITY_LABEL[severity],
                "object": change.obj,
                "message": mask_secrets(change.message),
                "old": mask_secrets(change.old),
                "new": mask_secrets(change.new),
            }
        )
    return rows


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------

def _root(settings) -> Path:
    return Path(settings.storage_root).expanduser().resolve()


def record(settings, device, ip: str | None, changes: list[Change]) -> None:
    """Append the detected changes of one device to the audit log."""
    if not changes:
        return
    entry = {
        "time": datetime.now(dt_timezone.utc).isoformat(timespec="seconds"),
        "device_id": device.pk,
        "device": str(device),
        "ip": ip or "",
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
    counts = {key: 0 for key, _ in SEVERITIES}
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
                {"name": entry.get("device", "?"), "ip": entry.get("ip", ""), "changes": []},
            )
            device["changes"].append(
                {
                    **change,
                    "when": entry["when"],
                    "severity": severity,
                    "severity_label": SEVERITY_LABEL[severity],
                    "category_label": AUDIT_CATEGORY_LABEL.get(category, category),
                }
            )

    ordered = sorted(devices.values(), key=lambda device: device["name"].lower())
    for device in ordered:
        device["changes"].sort(key=lambda change: (-SEVERITY_RANK[change["severity"]], change["when"]))
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


def build_preview(settings, device, ip: str | None, changes: list[Change], since: datetime, until: datetime) -> dict:
    """Audit report for a single comparison, as it would be sent to the security manager."""
    entry = {
        "device": str(device),
        "ip": ip or "",
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


def render_report(settings, report: dict) -> tuple[str, str, str]:
    """Return (subject, plain text, HTML) of the audit e-mail."""
    fields = [field for field in (getattr(settings, "audit_fields", None) or DEFAULT_AUDIT_FIELDS)]
    labels = dict(AUDIT_FIELDS)
    period = f"{_format_time(report['since'], settings)} - {_format_time(report['until'], settings)}"
    counts = report["counts"]
    summary = ", ".join(f"{counts[key]} {label.lower()}" for key, label in reversed(SEVERITIES) if counts[key])

    subject = (
        f"[LibreOXI] Configuration change audit: {len(report['devices'])} device(s), "
        f"{report['total']} change(s)" + (f" ({summary})" if summary else "")
    )

    def cell(change, field):
        if field == "time":
            return _format_time(change["when"], settings)
        if field == "ip":
            return device_ip
        if field == "severity":
            return change["severity_label"]
        if field == "category":
            return change["category_label"]
        if field == "change":
            return change["message"]
        return change.get(field, "")

    text = [f"LibreOXI configuration change audit", f"Period: {period}", ""]
    html = [
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#212529">',
        "<h2 style=\"margin:0 0 4px\">LibreOXI configuration change audit</h2>",
        f"<p style=\"margin:0 0 16px;color:#6c757d\">Period: {escape(period)}</p>",
    ]
    if not report["devices"]:
        text.append("No configuration changes matching the audit settings were detected.")
        html.append("<p>No configuration changes matching the audit settings were detected.</p>")
    else:
        text.append(f"Changes: {report['total']}" + (f" ({summary})" if summary else ""))
        text.append("")
        html.append(f"<p><strong>Changes:</strong> {report['total']}" + (f" ({escape(summary)})" if summary else "") + "</p>")

    for device in report["devices"]:
        device_ip = device["ip"]
        title = device["name"] + (f" ({device_ip})" if device_ip and "ip" in fields else "")
        text.append(f"== {title} ==")
        html.append(f"<h3 style=\"margin:20px 0 6px\">{escape(title)}</h3>")
        columns = [field for field in fields if field != "ip"]
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


def send_report(settings, since: datetime, until: datetime, force: bool = False) -> dict:
    """Build and send the audit e-mail. Returns {"sent": bool, "total": int, "reason": str}."""
    from django.core.mail import EmailMultiAlternatives

    to = recipients(settings)
    if not to:
        return {"sent": False, "total": 0, "reason": "No audit e-mail recipients are configured."}
    report = build_report(settings, since, until)
    if not report["total"] and not force and not getattr(settings, "audit_send_empty", False):
        return {"sent": False, "total": 0, "reason": "No changes to report."}
    subject, text, html = render_report(settings, report)
    message = EmailMultiAlternatives(subject=subject, body=text, to=to)
    message.attach_alternative(html, "text/html")
    message.send(fail_silently=False)
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


def due_slot(settings, now: datetime) -> datetime | None:
    """Return today's send time if the daily e-mail is due and not yet sent, else None."""
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
    return slot


def default_window_start(settings, until: datetime) -> datetime:
    last_sent = read_last_sent(settings)
    earliest = until - timedelta(days=7)
    if last_sent is None:
        return until - timedelta(hours=24)
    return max(last_sent, earliest)
