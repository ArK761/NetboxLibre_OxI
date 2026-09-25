"""Configuration change audit: severity classification, audit log and daily e-mail."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from html import escape
from pathlib import Path

from .config_changes import Change


SEVERITIES = (
    ("low", "Nízka"),
    ("medium", "Stredná"),
    ("high", "Vysoká"),
    ("critical", "Kritická"),
)
SEVERITY_PLURAL = {"low": "nízke", "medium": "stredné", "high": "vysoké", "critical": "kritické"}
SEVERITY_RANK = {key: rank for rank, (key, _) in enumerate(SEVERITIES)}
SEVERITY_LABEL = dict(SEVERITIES)

AUDIT_CATEGORIES = (
    ("firewall", "Firewall / ACL / VPN (pravidlá, NAT, aliasy, VPN)", "critical"),
    ("access", "Používatelia a prístup (účty, heslá, AAA)", "critical"),
    ("management", "Správa zariadenia (SNMP, SSH/HTTP, logovanie, NTP, manažment VLAN)", "high"),
    ("routing", "Smerovanie (statické trasy, OSPF, BGP, brána)", "high"),
    ("vlan", "VLAN (pridané/odstránené VLAN, VLAN na portoch)", "medium"),
    ("port", "Porty (vypnutie/zapnutie, port security)", "medium"),
    ("description", "Popisy a názvy (popis portu, názov VLAN, názov zariadenia)", "low"),
    ("other", "Ostatné zmeny", "low"),
)
AUDIT_CATEGORY_LABEL = {key: label.split(" (")[0] for key, label, _ in AUDIT_CATEGORIES}
DEFAULT_SEVERITY = {key: severity for key, _, severity in AUDIT_CATEGORIES}

AUDIT_FIELDS = (
    ("time", "Čas"),
    ("ip", "IP zariadenia"),
    ("severity", "Závažnosť"),
    ("category", "Kategória"),
    ("change", "Zmena"),
    ("old", "Pôvodný riadok"),
    ("new", "Nový riadok"),
)
DEFAULT_AUDIT_FIELDS = ["time", "ip", "severity", "category", "change"]

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


LABEL_SK = {
    "description": "popis",
    "name": "názov",
    "alias": "alias",
    "hostname": "názov zariadenia",
    "access VLAN": "prístupová VLAN",
    "allowed VLANs": "povolené VLAN",
    "native VLAN (PVID)": "natívna VLAN (PVID)",
    "native VLAN": "natívna VLAN",
    "untagged VLANs": "netagované VLAN",
    "tagged VLANs": "tagované VLAN",
    "member VLANs": "členské VLAN",
    "excluded VLANs": "vylúčené VLAN",
    "VLAN members": "členovia VLAN",
    "port mode": "režim portu",
    "untagged ports": "netagované porty",
    "tagged ports": "tagované porty",
    "IPv6 address": "IPv6 adresa",
    "IP address": "IP adresa",
    "ipaddr": "IP adresa",
    "subnet": "maska siete",
    "VLAN ID": "VLAN ID",
    "speed": "rýchlosť",
    "location": "umiestnenie",
    "syslocation": "umiestnenie (SNMP)",
    "contact": "kontakt",
    "action": "akcia",
    "interface": "rozhranie",
    "protocol": "protokol",
    "port": "port",
    "power inline priority": "priorita PoE",
    "power inline": "PoE",
    "bcrypt-hash": "heslo",
    "sha512-hash": "heslo",
    "password": "heslo",
    "rocommunity": "SNMP community",
    "rwcommunity": "SNMP community",
}
MODE_SK = {"tagged": "tagovane", "untagged": "netagovane", "allowed": "povolená", "member": "ako člen"}


def _label(label: str) -> str:
    return LABEL_SK.get(label, label)


def _details(details: str) -> str:
    """"name tech, description Technician" -> "názov: tech, popis: Technician"."""
    parts = []
    for part in re.split(r",\s+(?=[A-Za-z])", details):
        for english in sorted(LABEL_SK, key=len, reverse=True):
            if part.startswith(english + " "):
                part = f"{LABEL_SK[english]}: {part[len(english) + 1:]}"
                break
        parts.append(part)
    return ", ".join(parts)


def _object_name(obj: str) -> str:
    """English object names from the parser -> Slovak names for the audit."""
    if obj in ("Global configuration", ""):
        return "Zariadenie"
    obj = re.sub(r" \(interface\)$", "", obj)
    obj = re.sub(r"^Interface ((?:wan|lan|opt\d+)\b)", r"Rozhranie \1", obj)
    obj = re.sub(r"^Interface ", "Port ", obj)
    obj = re.sub(r'^Firewall > rule ("[^"]*"|\S+)', r"Pravidlo firewallu \1", obj)
    obj = re.sub(r"^NAT > ", "NAT > ", obj)
    obj = re.sub(r"^Firewall alias ", "Alias firewallu ", obj)
    obj = re.sub(r"^User ", "Používateľský účet ", obj)
    obj = re.sub(r"^Group ", "Skupina ", obj)
    obj = re.sub(r"^system > ", "Systém > ", obj)
    obj = re.sub(r"^snmpd\b", "SNMP", obj)
    return obj.replace(" > destination", " > cieľ").replace(" > source", " > zdroj")


def _list(value: str) -> str:
    return ", ".join(part for part in re.split(r"\s*,\s*", value.strip()) if part)


def _vlan_details(details: str) -> tuple[str, str]:
    """MikroTik details "bridge bridge1, tagged a,b, comment "x"" -> readable sentence part."""
    items = dict(re.findall(r'(name|bridge|interface|tagged|untagged|comment)\s+("[^"]*"|[^\s,]+(?:,[^\s,]+)*)', details))
    parts = []
    label = items.get("comment") or items.get("name")
    if items.get("bridge"):
        parts.append(f"na {items['bridge']}")
    elif items.get("interface"):
        parts.append(f"na {items['interface']}")
    if items.get("tagged"):
        parts.append(f"tagovaná na portoch {_list(items['tagged'])}")
    if items.get("untagged"):
        parts.append(f"netagovaná na portoch {_list(items['untagged'])}")
    return (f" {label}" if label else ""), ", ".join(parts)


def _ports(ports: list[str], singular: str, plural: str) -> str:
    if len(ports) == 1:
        return f"Port {ports[0]} {singular}"
    return f"Porty {', '.join(ports)} {plural}"


def audit_text(change: dict) -> str:
    """Plain-language (Slovak) description of a change for the security manager, without config lines."""
    message = change.get("message", "")

    # MikroTik bridge VLAN entry
    match = re.match(r"^VLAN (\S+) (added|removed) \((.*)\)$", message)
    if match and re.search(r"\b(bridge|tagged|untagged|interface) ", match.group(3)):
        label, where = _vlan_details(match.group(3))
        verb = "bola pridaná" if match.group(2) == "added" else "bola odstránená"
        return f"VLAN {match.group(1)}{label} {verb}" + (f" ({where})." if where else ".")

    match = re.match(r"^VLAN (.+?)(?: \(interface\))? (added|removed)(?: \((.*)\))?$", message)
    if match:
        verb = "bola pridaná" if match.group(2) == "added" else "bola odstránená"
        details = f" ({_details(match.group(3))})" if match.group(3) else ""
        return f"VLAN {match.group(1)} {verb}{details}."

    match = re.match(r"^Interface (.+?) (added|removed)(?: \((.*)\))?$", message)
    if match:
        verb = "bol pridaný" if match.group(2) == "added" else "bol odstránený"
        details = f" ({_details(match.group(3))})" if match.group(3) else ""
        return f"{_object_name('Interface ' + match.group(1))} {verb}{details}."

    match = re.match(r"^VLAN list changed .*\((.*)\)$", message)
    if match:
        sentences = [
            f"VLAN {vlans} {'pridaná do databázy VLAN' if action == 'added' else 'odstránená z databázy VLAN'}"
            for action, vlans in re.findall(r"(added|removed) ([\d,\-]+)", match.group(1))
        ]
        return "; ".join(sentences) + "."

    match = re.match(r'^VLAN (\S+): (tagged|untagged) changed "(.*)" -> "(.*)"$', message)
    if match:
        old_ports = {port for port in match.group(3).split(",") if port}
        new_ports = {port for port in match.group(4).split(",") if port}
        mode = MODE_SK[match.group(2)]
        sentences = []
        if new_ports - old_ports:
            sentences.append(f"{_ports(sorted(new_ports - old_ports), 'pridaný', 'pridané')} do VLAN {match.group(1)} ({mode})")
        if old_ports - new_ports:
            sentences.append(f"{_ports(sorted(old_ports - new_ports), 'odobratý', 'odobraté')} z VLAN {match.group(1)} ({mode})")
        if sentences:
            return "; ".join(sentences) + "."

    match = re.match(r"^/user name=(\S+): (.+) changed$", message)
    if match:
        label = _label(match.group(2))
        return f"Používateľský účet {match.group(1)}: " + ("zmenené heslo." if label == "heslo" else f"zmena – {label}.")

    match = re.match(r"^(.+?): (snmp-server community|snmp-agent community|rocommunity|rwcommunity) changed$", message)
    if match:
        return "Zmenená SNMP community."

    match = re.match(r'^(/ip firewall \S+|/ipv6 firewall \S+): line (added|removed) "(?:add )?(.*)"$', message)
    if match:
        verb = "bolo pridané" if match.group(2) == "added" else "bolo odstránené"
        return f"Pravidlo firewallu {verb} ({match.group(1)}): {match.group(3)}"

    match = re.match(r"^(.+?): (tagged|untagged|allowed|member) VLANs changed .*\((.*)\)$", message)
    if match:
        port, mode, delta = _object_name(match.group(1)), MODE_SK[match.group(2)], match.group(3)
        port_lower = port[0].lower() + port[1:]
        sentences = [
            f"VLAN {vlans} {'pridaná na' if action == 'added' else 'odobratá z'} {port_lower} ({mode})"
            for action, vlans in re.findall(r"(added|removed) ([\d,\-]+)", delta)
        ]
        return "; ".join(sentences) + "."

    match = re.match(r'^Hostname changed "(.*)" -> "(.*)"$', message)
    if match:
        return f'Zariadenie premenované z "{match.group(1)}" na "{match.group(2)}".'

    match = re.match(r"^(User|Group) (\S+) (added|removed)(?: \((.*)\))?$", message)
    if match:
        kind = "Používateľský účet" if match.group(1) == "User" else "Skupina používateľov"
        created = "bol vytvorený" if match.group(1) == "User" else "bola vytvorená"
        deleted = "bol zmazaný" if match.group(1) == "User" else "bola zmazaná"
        return f"{kind} {match.group(2)} {created if match.group(3) == 'added' else deleted}."

    match = re.match(r"^User (\S+) changed", message)
    if match:
        return f"Používateľský účet {match.group(1)} bol upravený (heslo, oprávnenia alebo iné nastavenia)."

    match = re.match(r'^(.+?): (.+?) changed "(.*)" -> "(.*)"(.*)$', message)
    if match:
        return f'{_object_name(match.group(1))}: {_label(match.group(2))} – zmena z "{match.group(3)}" na "{match.group(4)}".'

    match = re.match(r"^(.+?): administratively (enabled|disabled)", message)
    if match:
        state = "administratívne zapnutý" if match.group(2) == "enabled" else "administratívne vypnutý (shutdown)"
        return f"{_object_name(match.group(1))}: {state}."

    match = re.match(r'^(.+?): line (added|removed) "(.*)"$', message)
    if match:
        verb = "Pridaný" if match.group(2) == "added" else "Odstránený"
        return f"{verb} konfiguračný riadok ({_object_name(match.group(1))}): {match.group(3)}"

    match = re.match(r'^(.+?): (.+?) (added|removed) "(.*)"$', message)
    if match:
        verb = "pridané" if match.group(3) == "added" else "odstránené"
        return f'{_object_name(match.group(1))}: {_label(match.group(2))} – {verb} "{match.group(4)}".'

    match = re.match(r"^(.+?): (.+) changed$", message)
    if match:
        label = _label(match.group(2))
        if label == "heslo":
            return f"{_object_name(match.group(1))}: zmenené heslo."
        return f"{_object_name(match.group(1))}: zmena – {label}."

    match = re.match(r'^Firewall > rule ("[^"]*"|\S+) (added|removed)(?: \((.*)\))?$', message)
    if match:
        verb = "bolo pridané" if match.group(2) == "added" else "bolo odstránené"
        details = re.sub(r",?\s*description [^,]*$", "", match.group(3) or "")
        return f"Pravidlo firewallu {match.group(1)} {verb}" + (f" ({_details(details)})." if details else ".")

    match = re.match(r"^(.+?) (added|removed)(?: \((.*)\))?$", message)
    if match:
        verb = "Pridané" if match.group(2) == "added" else "Odstránené"
        details = match.group(3) or ""
        details = re.sub(r",?\s*description [^,]*$", "", details) if match.group(1).startswith("Firewall > rule") else details
        return f"{verb}: {_object_name(match.group(1))}" + (f" ({_details(details)})." if details else ".")

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
                {"name": entry.get("device", "?"), "ip": entry.get("ip", ""), "changes": [], "authors": []},
            )
            author = entry.get("author") or ""
            if author and author not in device["authors"]:
                device["authors"].append(author)
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


def render_report(settings, report: dict) -> tuple[str, str, str]:
    """Return (subject, plain text, HTML) of the audit e-mail."""
    fields = [field for field in (getattr(settings, "audit_fields", None) or DEFAULT_AUDIT_FIELDS)]
    labels = dict(AUDIT_FIELDS)
    period = f"{_format_time(report['since'], settings)} - {_format_time(report['until'], settings)}"
    counts = report["counts"]
    summary = ", ".join(f"{SEVERITY_PLURAL[key]}: {counts[key]}" for key, _label in reversed(SEVERITIES) if counts[key])

    subject = (
        f"[LibreOXI] Audit zmien konfigurácie – zariadenia: {len(report['devices'])}, "
        f"zmeny: {report['total']}" + (f" ({summary})" if summary else "")
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
            return audit_text(change)
        return change.get(field, "")

    text = ["Audit zmien konfigurácie sieťových zariadení (LibreOXI)", f"Obdobie: {period}", ""]
    html = [
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#212529">',
        "<h2 style=\"margin:0 0 4px\">Audit zmien konfigurácie sieťových zariadení</h2>",
        f"<p style=\"margin:0 0 16px;color:#6c757d\">Obdobie: {escape(period)}</p>",
    ]
    if not report["devices"]:
        text.append("Neboli zistené žiadne zmeny zodpovedajúce nastaveniam auditu.")
        html.append("<p>Neboli zistené žiadne zmeny zodpovedajúce nastaveniam auditu.</p>")
    else:
        text.append(f"Počet zmien: {report['total']}" + (f" ({summary})" if summary else ""))
        text.append("")
        html.append(f"<p><strong>Počet zmien:</strong> {report['total']}" + (f" ({escape(summary)})" if summary else "") + "</p>")

    for device in report["devices"]:
        device_ip = device["ip"]
        title = device["name"] + (f" ({device_ip})" if device_ip and "ip" in fields else "")
        text.append(f"== {title} ==")
        html.append(f"<h3 style=\"margin:20px 0 6px\">{escape(title)}</h3>")
        for author in device.get("authors", []):
            text.append(f"Zmenu uložil: {author}")
            html.append(f"<p style=\"margin:0 0 6px;color:#495057\">Zmenu uložil: {escape(author)}</p>")
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
        return {"sent": False, "total": 0, "reason": "Nie sú nastavení príjemcovia auditného e-mailu."}
    report = build_report(settings, since, until)
    if not report["total"] and not force and not getattr(settings, "audit_send_empty", False):
        return {"sent": False, "total": 0, "reason": "Žiadne zmeny na odoslanie."}
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
