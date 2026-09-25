"""NetBox Self audit: who changed what in NetBox itself (from the NetBox changelog).

The rules (SelfAuditRule) say which fields of which NetBox object types are watched,
with a severity and an optional message template. The data comes from NetBox's own
changelog (core.ObjectChange), so the audit reaches back as far as NetBox keeps it
(CHANGELOG_RETENTION, 90 days by default). NetBox version and plugin changes are
recorded by the plugin itself (SelfAuditSystemEvent).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone as dt_timezone
from html import escape

from .audit import SEVERITY_COLOR, SEVERITY_KEYS, SEVERITY_RANK, _format_time, severity_label
from .i18n import language_of, tr


CREATE = "__create__"
DELETE = "__delete__"
EVENTS = (CREATE, DELETE)

# Apps whose object types can be watched.
WATCH_APPS = ("dcim", "ipam", "tenancy", "virtualization", "circuits", "wireless", "vpn", "extras")
SKIP_FIELDS = {"id", "created", "last_updated", "custom_field_data"}
MAX_CHANGES = 20000  # safety limit for very long periods


# --------------------------------------------------------------------------
# Object types and fields
# --------------------------------------------------------------------------

def _label(text) -> str:
    text = str(text or "")
    return text[:1].upper() + text[1:]


def type_key(model) -> str:
    return f"{model._meta.app_label}.{model._meta.model_name}"


def model_for(key: str):
    from django.apps import apps

    try:
        app_label, model_name = key.split(".", 1)
        return apps.get_model(app_label, model_name)
    except (LookupError, ValueError):
        return None


def type_label(key: str) -> str:
    model = model_for(key)
    return _label(model._meta.verbose_name) if model is not None else key


def watchable_types() -> list[tuple[str, list[tuple[str, str]]]]:
    """[(app verbose name, [(key, label), ...]), ...] of NetBox object types with a changelog."""
    from django.apps import apps

    groups = []
    for app_label in WATCH_APPS:
        try:
            config = apps.get_app_config(app_label)
        except LookupError:
            continue
        models = [
            model for model in config.get_models()
            if not model._meta.auto_created and not model._meta.proxy and hasattr(model, "to_objectchange")
        ]
        if not models:
            continue
        items = sorted(((type_key(model), _label(model._meta.verbose_name)) for model in models), key=lambda item: item[1].lower())
        groups.append((_label(config.verbose_name), items))
    return groups


def custom_fields(key: str) -> list:
    """Custom fields assigned to the object type."""
    try:
        from extras.models import CustomField
    except ImportError:
        return []
    app_label, _, model_name = key.partition(".")
    for lookup in ("object_types", "content_types"):
        try:
            return list(
                CustomField.objects.filter(**{f"{lookup}__app_label": app_label, f"{lookup}__model": model_name}).order_by("name")
            )
        except Exception:  # field name differs between NetBox versions
            continue
    return []


def discover_fields(key: str) -> list[tuple[str, str, str]]:
    """[(field key, label, kind)] of an object type; kind is "field" or "custom"."""
    model = model_for(key)
    if model is None:
        return []
    fields = []
    names = set()
    for field in model._meta.get_fields():
        if field.auto_created and not field.concrete:
            continue  # reverse relations
        if not (getattr(field, "concrete", False) or getattr(field, "many_to_many", False)):
            continue
        name = field.name
        if name in SKIP_FIELDS or name.startswith("_") or name in names:
            continue
        names.add(name)
        fields.append((name, _label(getattr(field, "verbose_name", name)), "field"))
    if hasattr(model, "tags") and "tags" not in names:
        fields.append(("tags", "Tags", "field"))
    for custom_field in custom_fields(key):
        fields.append((f"cf:{custom_field.name}", _label(custom_field.label or custom_field.name), "custom"))
    return fields


def field_label(key: str, field: str, lang: str = "en") -> str:
    if field == CREATE:
        return tr("self.event_create", lang)
    if field == DELETE:
        return tr("self.event_delete", lang)
    for name, label, _kind in discover_fields(key):
        if name == field:
            return label
    return field.removeprefix("cf:")


# --------------------------------------------------------------------------
# Values and differences
# --------------------------------------------------------------------------

class _Resolver:
    """Turns primary keys and choice values from changelog snapshots into readable text."""

    def __init__(self):
        self.cache = {}
        self.custom = {}

    def obj(self, model, pk) -> str:
        if model is None:
            return str(pk)
        key = (model, pk)
        if key not in self.cache:
            try:
                found = model.objects.filter(pk=pk).first()
            except Exception:
                found = None
            self.cache[key] = str(found) if found is not None else f"#{pk}"
        return self.cache[key]

    def custom_field(self, type_key_: str, name: str):
        if type_key_ not in self.custom:
            self.custom[type_key_] = {field.name: field for field in custom_fields(type_key_)}
        return self.custom[type_key_].get(name)

    def display(self, key: str, field: str, value):
        """Readable value: a string, or a list of strings for multi-value fields."""
        if value is None or value == "":
            return ""
        related = None
        choices = {}
        if field.startswith("cf:"):
            custom_field = self.custom_field(key, field[3:])
            if custom_field is not None and getattr(custom_field, "type", "") in ("object", "multiobject"):
                related_type = getattr(custom_field, "related_object_type", None)
                related = related_type.model_class() if related_type is not None else None
        else:
            model = model_for(key)
            try:
                model_field = model._meta.get_field(field) if model is not None else None
            except Exception:
                model_field = None
            if model_field is not None:
                if model_field.is_relation and field != "tags":
                    related = model_field.related_model
                elif getattr(model_field, "choices", None):
                    choices = {str(choice): str(label) for choice, label in model_field.flatchoices}
        if isinstance(value, list):
            return [self._one(item, related, choices) for item in value]
        return self._one(value, related, choices)

    def _one(self, value, related, choices) -> str:
        if isinstance(value, dict):
            if "name" in value:
                return str(value["name"])
            if related is not None and "id" in value:
                return self.obj(related, value["id"])
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        if related is not None and isinstance(value, (int, str)) and str(value).isdigit():
            return self.obj(related, int(value))
        if isinstance(value, bool):
            return "✓" if value else "✗"
        return choices.get(str(value), str(value))


def _raw(data: dict | None, field: str):
    data = data or {}
    if field.startswith("cf:"):
        return (data.get("custom_fields") or {}).get(field[3:])
    return data.get(field)


def _same(old, new) -> bool:
    if isinstance(old, list) and isinstance(new, list):
        try:
            return sorted(json.dumps(item, sort_keys=True) for item in old) == sorted(json.dumps(item, sort_keys=True) for item in new)
        except TypeError:
            return old == new
    return (old in (None, "", [])) and (new in (None, "", [])) or old == new


def difference(resolver: _Resolver, key: str, field: str, old_raw, new_raw) -> dict | None:
    """What changed in one field, or None.

    kind "list": multi-value field -> added / removed items
    kind "lines": multi-line text -> added / removed lines
    kind "value": anything else -> old / new
    """
    if _same(old_raw, new_raw):
        return None
    old = resolver.display(key, field, old_raw)
    new = resolver.display(key, field, new_raw)
    if isinstance(old, list) or isinstance(new, list):
        old = old if isinstance(old, list) else ([old] if old else [])
        new = new if isinstance(new, list) else ([new] if new else [])
        added = [item for item in new if item not in old]
        removed = [item for item in old if item not in new]
        if not added and not removed:
            return None
        return {"kind": "list", "old": ", ".join(old), "new": ", ".join(new), "added": added, "removed": removed}
    if "\n" in old or "\n" in new:
        old_lines = [line.rstrip() for line in old.splitlines() if line.strip()]
        new_lines = [line.rstrip() for line in new.splitlines() if line.strip()]
        added = [line for line in new_lines if line not in old_lines]
        removed = [line for line in old_lines if line not in new_lines]
        if not added and not removed:
            return None
        return {"kind": "lines", "old": old, "new": new, "added": added, "removed": removed}
    if old == new:
        return None
    return {"kind": "value", "old": old, "new": new, "added": [], "removed": []}


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

PLACEHOLDERS = ("user", "object", "object_type", "field", "old", "new", "added", "removed", "changes", "action")


class _Keep(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def render_message(template: str, values: dict) -> str:
    """Fill {placeholders}; unknown ones are left as they are, a broken template is shown unchanged."""
    try:
        return template.format_map(_Keep(values))
    except (ValueError, IndexError, AttributeError, KeyError):
        return template


def _changes_text(diff: dict, lang: str) -> str:
    if diff["kind"] == "value":
        if not diff["old"]:
            return tr("self.chg_set", lang, new=diff["new"])
        if not diff["new"]:
            return tr("self.chg_cleared", lang, old=diff["old"])
        return tr("self.chg_value", lang, old=diff["old"], new=diff["new"])
    parts = []
    if diff["kind"] == "lines":
        if diff["added"]:
            parts.append(tr("self.chg_lines_added", lang, count=len(diff["added"])))
        if diff["removed"]:
            parts.append(tr("self.chg_lines_removed", lang, count=len(diff["removed"])))
    else:
        if diff["added"]:
            parts.append(tr("self.chg_added", lang, items=", ".join(diff["added"])))
        if diff["removed"]:
            parts.append(tr("self.chg_removed", lang, items=", ".join(diff["removed"])))
    return "; ".join(parts)


def default_message(field: str) -> str:
    if field == CREATE:
        return "self.msg_create"
    if field == DELETE:
        return "self.msg_delete"
    return "self.msg_update"


def message_for(rule, values: dict, lang: str) -> str:
    template = (rule.message or "").strip() or tr(default_message(rule.field), lang)
    return render_message(template, values)


# --------------------------------------------------------------------------
# NetBox version and plugins
# --------------------------------------------------------------------------

def system_snapshot() -> dict:
    """{"netbox": version, "plugins": {name: version}} of the running NetBox."""
    import importlib

    from django.conf import settings as django_settings

    plugins = {}
    for name in getattr(django_settings, "PLUGINS", []) or []:
        version = ""
        try:
            version = str(getattr(getattr(importlib.import_module(name), "config", None), "version", "") or "")
        except Exception:
            pass
        plugins[name] = version
    return {"netbox": str(getattr(django_settings, "VERSION", "") or ""), "plugins": plugins}


def check_system(settings, now: datetime | None = None) -> int:
    """Record NetBox version / plugin changes since the last check. Returns the number of new events."""
    from django.utils import timezone

    from .models import SelfAuditSystemEvent

    current = system_snapshot()
    previous = getattr(settings, "self_audit_snapshot", None) or {}
    if previous == current:
        return 0
    now = now or timezone.now()
    events = []
    if previous:  # the first run only stores the baseline
        if previous.get("netbox") != current["netbox"]:
            events.append(SelfAuditSystemEvent(time=now, kind="netbox", name="NetBox", old=previous.get("netbox", ""), new=current["netbox"]))
        old_plugins = previous.get("plugins", {}) or {}
        for name, version in current["plugins"].items():
            if name not in old_plugins:
                events.append(SelfAuditSystemEvent(time=now, kind="plugin_added", name=name, new=version))
            elif old_plugins[name] != version:
                events.append(SelfAuditSystemEvent(time=now, kind="plugin_version", name=name, old=old_plugins[name], new=version))
        for name, version in old_plugins.items():
            if name not in current["plugins"]:
                events.append(SelfAuditSystemEvent(time=now, kind="plugin_removed", name=name, old=version))
    SelfAuditSystemEvent.objects.bulk_create(events)
    settings.self_audit_snapshot = current
    settings.save(update_fields=["self_audit_snapshot"])
    return len(events)


def _system_text(event, lang: str) -> str:
    if event.kind in ("plugin_added", "plugin_removed"):
        version = event.new if event.kind == "plugin_added" else event.old
        return tr(f"self.sys_{event.kind}", lang, name=f"{event.name} {version}".strip())
    return tr(f"self.sys_{event.kind}", lang, name=event.name, old=event.old or "-", new=event.new or "-")


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def rules_by_type(types: list[str] | None = None) -> dict[str, dict]:
    from .models import SelfAuditRule

    rules: dict[str, dict] = {}
    queryset = SelfAuditRule.objects.filter(enabled=True)
    if types:
        queryset = queryset.filter(object_type__in=types)
    for rule in queryset:
        rules.setdefault(rule.object_type, {})[rule.field] = rule
    return rules


def _object_changes(keys: list[str], since, until):
    try:
        from core.models import ObjectChange
    except ImportError:  # NetBox < 4.0
        from extras.models import ObjectChange
    from django.contrib.contenttypes.models import ContentType

    type_ids = {}
    for key in keys:
        app_label, _, model_name = key.partition(".")
        try:
            type_ids[ContentType.objects.get_by_natural_key(app_label, model_name).pk] = key
        except ContentType.DoesNotExist:
            continue
    if not type_ids:
        return [], type_ids
    queryset = ObjectChange.objects.filter(changed_object_type_id__in=list(type_ids))
    if since is not None:
        queryset = queryset.filter(time__gte=since)
    if until is not None:
        queryset = queryset.filter(time__lt=until)
    return list(queryset.select_related("user").order_by("time")[:MAX_CHANGES]), type_ids


def _url(name: str, pk) -> str:
    from django.urls import NoReverseMatch, reverse

    try:
        return reverse(name, kwargs={"pk": pk})
    except NoReverseMatch:
        return ""


def _object_url(key: str, pk) -> str:
    app_label, _, model_name = key.partition(".")
    return _url(f"{app_label}:{model_name}", pk)


def collect(settings, since, until, types: list[str] | None = None) -> list[dict]:
    """Audit entries of the period (all severities), oldest first."""
    from .models import SelfAuditSystemEvent

    lang = language_of(settings)
    rules = rules_by_type(types)
    entries = []
    resolver = _Resolver()
    changes, type_ids = _object_changes(list(rules), since, until) if rules else ([], {})
    labels = {key: type_label(key) for key in type_ids.values()}
    field_labels: dict[str, dict] = {}

    for change in changes:
        key = type_ids.get(change.changed_object_type_id)
        type_rules = rules.get(key, {})
        user = change.user_name or (str(change.user) if change.user_id else "") or "?"
        base = {
            "when": change.time,
            "user": user,
            "object": change.object_repr,
            "object_type": labels.get(key, key),
            "object_type_key": key,
            "object_url": _object_url(key, change.changed_object_id) if change.action != "delete" else "",
            "changelog_url": _url("core:objectchange", change.pk),
            "action": change.action,
        }
        values = {"user": user, "object": change.object_repr, "object_type": base["object_type"], "action": change.action}
        if change.action in ("create", "delete"):
            rule = type_rules.get(CREATE if change.action == "create" else DELETE)
            if rule is None:
                continue
            values.update({"field": "", "old": "", "new": "", "added": "", "removed": "", "changes": ""})
            entries.append({
                **base, "severity": rule.severity, "field": rule.field, "field_label": field_label(key, rule.field, lang),
                "kind": "event", "old": "", "new": "", "added": [], "removed": [], "text": message_for(rule, values, lang),
            })
            continue
        if field_labels.get(key) is None:
            field_labels[key] = {name: label for name, label, _kind in discover_fields(key)}
        for field, rule in type_rules.items():
            if field in EVENTS:
                continue
            diff = difference(resolver, key, field, _raw(change.prechange_data, field), _raw(change.postchange_data, field))
            if diff is None:
                continue
            label = field_labels[key].get(field, field.removeprefix("cf:"))
            values.update({
                "field": label, "old": diff["old"], "new": diff["new"],
                "added": ", ".join(diff["added"]), "removed": ", ".join(diff["removed"]),
                "changes": _changes_text(diff, lang),
            })
            entries.append({
                **base, **diff, "severity": rule.severity, "field": field, "field_label": label,
                "text": message_for(rule, values, lang),
            })

    if not types or "netbox.system" in types:
        events = SelfAuditSystemEvent.objects.all()
        if since is not None:
            events = events.filter(time__gte=since)
        if until is not None:
            events = events.filter(time__lt=until)
        for event in events:
            entries.append({
                "when": event.time, "user": "", "object": event.name, "object_type": "NetBox", "object_type_key": "netbox.system",
                "object_url": "", "changelog_url": "", "action": "system", "severity": "critical", "field": event.kind,
                "field_label": "", "kind": "event", "old": event.old, "new": event.new, "added": [], "removed": [],
                "text": _system_text(event, lang),
            })

    entries.sort(key=lambda entry: entry["when"])
    return entries


def build_report(settings, since, until, label: str, types: list[str] | None = None, min_severity: str | None = None) -> dict:
    from django.utils import timezone

    lang = language_of(settings)
    minimum = SEVERITY_RANK.get(min_severity or getattr(settings, "self_audit_min_severity", "low") or "low", 0)
    counts = {key: 0 for key in SEVERITY_KEYS}
    kept = []
    skipped = 0
    for entry in collect(settings, since, until, types):
        severity = entry["severity"] if entry["severity"] in SEVERITY_RANK else "low"
        if SEVERITY_RANK[severity] < minimum:
            skipped += 1
            continue
        counts[severity] += 1
        kept.append({**entry, "severity": severity, "severity_label": severity_label(severity, lang)})
    return {
        "entries": kept,
        "counts": counts,
        "total": len(kept),
        "skipped": skipped,
        "since": since or datetime(1970, 1, 1, tzinfo=dt_timezone.utc),
        "until": until or timezone.now(),
        "period_label": label,
    }


def report_subject(settings, report: dict) -> str:
    lang = language_of(settings)
    summary = ", ".join(
        f"{tr(f'severity_plural.{key}', lang)}: {report['counts'][key]}" for key in reversed(SEVERITY_KEYS) if report["counts"][key]
    )
    return tr("self.subject", lang, total=report["total"]) + (f" ({summary})" if summary else "")


def render_report(settings, report: dict) -> tuple[str, str, str]:
    """(subject, plain text, HTML) of the NetBox Self audit."""
    lang = language_of(settings)
    subject = report_subject(settings, report)
    title = tr("self.title", lang)
    period = tr("report.period", lang, period=report["period_label"])
    columns = [tr("field.time", lang), tr("field.severity", lang), tr("self.col_user", lang), tr("self.col_object", lang), tr("field.change", lang)]
    text = [f"{title} (LibreOXI)", period, ""]
    html = [
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#212529">',
        f'<h2 style="margin:0 0 4px">{escape(title)}</h2>',
        f'<p style="margin:0 0 16px;color:#6c757d">{escape(period)}</p>',
    ]
    if not report["entries"]:
        text.append(tr("self.no_changes", lang))
        html.append(f"<p>{escape(tr('self.no_changes', lang))}</p></div>")
        return subject, "\n".join(text), "".join(html)

    text.extend([subject, ""])
    html.append(f"<p><strong>{escape(subject)}</strong></p>")
    html.append('<table style="border-collapse:collapse;width:100%" cellpadding="6"><tr>')
    html.extend(f'<th style="text-align:left;border-bottom:2px solid #dee2e6;background:#f8f9fa">{escape(column)}</th>' for column in columns)
    html.append("</tr>")
    for entry in report["entries"]:
        when = _format_time(entry["when"], settings)
        obj = f"{entry['object_type']}: {entry['object']}"
        text.append(" | ".join((when, entry["severity_label"], entry["user"] or "-", obj, entry["text"])))
        detail = []
        if entry["kind"] in ("list", "lines"):
            for item in entry["added"]:
                text.append(f"    + {item}")
                detail.append(f'<div style="color:#198754;font-family:monospace;font-size:12px">+ {escape(item)}</div>')
            for item in entry["removed"]:
                text.append(f"    - {item}")
                detail.append(f'<div style="color:#dc3545;font-family:monospace;font-size:12px">&minus; {escape(item)}</div>')
        badge = (
            f'<span style="color:#fff;background:{SEVERITY_COLOR[entry["severity"]]};padding:2px 6px;border-radius:4px">'
            f'{escape(entry["severity_label"])}</span>'
        )
        cells = (escape(when), badge, escape(entry["user"] or "-"), escape(obj), escape(entry["text"]) + "".join(detail))
        html.append("<tr>" + "".join(f'<td style="border-bottom:1px solid #dee2e6;vertical-align:top">{cell}</td>' for cell in cells) + "</tr>")
    html.append("</table></div>")
    return subject, "\n".join(text), "".join(html)


def html_document(settings, report: dict) -> str:
    subject, _text, html = render_report(settings, report)
    return (
        f'<!doctype html><html lang="{language_of(settings)}"><head><meta charset="utf-8">'
        f'<title>{escape(subject)}</title></head><body style="background:#fff;margin:24px">{html}</body></html>'
    )


def report_csv(settings, report: dict) -> str:
    import csv
    import io

    lang = language_of(settings)
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow([
        tr("field.time", lang), tr("field.severity", lang), tr("self.col_user", lang), tr("self.col_type", lang),
        tr("self.col_object", lang), tr("self.col_field", lang), tr("field.change", lang), tr("self.col_added", lang), tr("self.col_removed", lang),
    ])
    for entry in report["entries"]:
        writer.writerow([
            _format_time(entry["when"], settings), entry["severity_label"], entry["user"], entry["object_type"], entry["object"],
            entry["field_label"], entry["text"], "\n".join(entry["added"]), "\n".join(entry["removed"]),
        ])
    return "﻿" + buffer.getvalue()


def send_report(
    settings, since, until, label: str, to: list[str] | None = None, force: bool = False,
    attach_pdf: bool | None = None, pdf_password: str | None = None, types: list[str] | None = None,
    min_severity: str | None = None,
) -> dict:
    """E-mail the NetBox Self audit. Returns {"sent", "total", "reason", "reason_en"}."""
    from django.core.mail import EmailMultiAlternatives
    from django.utils import timezone

    from .audit import _deliver, from_address, recipients

    lang = language_of(settings)
    to = to or recipients(settings)
    if not to:
        return {"sent": False, "total": 0, "reason": tr("mail.no_recipients", lang), "reason_en": tr("mail.no_recipients", "en")}
    report = build_report(settings, since, until, label, types, min_severity)
    if not report["total"] and not force and not getattr(settings, "audit_send_empty", False):
        return {"sent": False, "total": 0, "reason": tr("mail.no_changes", lang), "reason_en": tr("mail.no_changes", "en")}
    if attach_pdf is None:
        attach_pdf = getattr(settings, "audit_email_attach_pdf", True)
    if pdf_password is None:
        pdf_password = getattr(settings, "audit_pdf_password", "") or ""
    subject, text, html = render_report(settings, report)
    message = EmailMultiAlternatives(subject=subject, body=text, from_email=from_address(settings), to=to)
    message.attach_alternative(html, "text/html")
    if attach_pdf:
        from .audit_pdf import build_self_pdf

        stamp = timezone.localtime().strftime("%Y-%m-%d")
        message.attach(f"netbox-self-audit_{stamp}.pdf", build_self_pdf(settings, report, subject, pdf_password or None), "application/pdf")
    _deliver(settings, message)
    return {"sent": True, "total": report["total"], "reason": ""}
