import json
from datetime import datetime, timezone
from pathlib import Path
from difflib import HtmlDiff, SequenceMatcher

from urllib.parse import quote

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.utils import timezone as django_timezone
from django.utils.safestring import mark_safe

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from . import audit, self_audit
from .config_changes import compare as compare_changes, config_author, summary as change_summary
from .forms import LibreOXIEmailForm, LibreOXISettingsForm
from .i18n import language_of, tr
from .models import LibreOXISettings, SelfAuditRule
from .oxi import fetch_device, monitored_devices
from .storage import device_dir, list_history, read_current


def format_timestamp(value, settings):
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = django_timezone.localtime(parsed)
        return parsed.strftime(settings.datetime_format)
    except (ValueError, TypeError):
        return value


def format_revision(name, settings):
    if name == "current.cfg":
        return "current.cfg"
    try:
        parsed = datetime.strptime(name.removesuffix(".cfg"), "%Y-%m-%d_%H-%M-%S").replace(tzinfo=timezone.utc)
        parsed = django_timezone.localtime(parsed)
        return parsed.strftime(settings.datetime_format)
    except (ValueError, TypeError):
        return name


def _parse_log_line(line, settings):
    parts = line.split(" ", 1)
    timestamp = format_timestamp(parts[0] if parts else "", settings)
    message = parts[1] if len(parts) > 1 else line
    event = "INFO"
    device_name = None
    display_message = message
    run_summary = None

    if message.startswith("CHANGE "):
        event = "CHANGE"
        payload = message[7:]
        device_name = payload.split(" configuration stored", 1)[0]
        display_message = "DEVICE BACKUP CHECK"
    elif message.startswith("NOCHANGE "):
        event = "NOCHANGE"
        payload = message[9:]
        device_name = payload.split(" ", 1)[0]
        display_message = "DEVICE BACKUP CHECK"
    elif message.startswith("ERROR "):
        event = "ERROR"
        payload = message[6:]
        device_name = payload.split(" LibreNMS ", 1)[0]
        display_message = "DEVICE BACKUP CHECK"
    elif message.startswith("INFO scheduled refresh finished"):
        event = "SCHEDULER"
        fields = {}
        for token in message.split()[4:]:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value

        def integer(name):
            try:
                return int(fields.get(name, "0"))
            except (ValueError, TypeError):
                return 0

        run_summary = {
            "run": fields.get("run", ""),
            "started": format_timestamp(fields.get("started"), settings),
            "finished": format_timestamp(fields.get("finished"), settings),
            "devices": integer("devices"),
            "change": integer("change"),
            "nochange": integer("nochange"),
            "error": integer("error"),
            "duration": integer("duration"),
        }
        display_message = "SCHEDULED CHECK"
    elif message.startswith("INFO scheduled refresh started"):
        event = "SCHEDULER_START"
        display_message = "SCHEDULED CHECK STARTED"

    return {
        "timestamp": timestamp,
        "message": message,
        "display_message": display_message,
        "event": event,
        "device_name": device_name,
        "run_summary": run_summary,
    }


PAGE_FIRST = 10  # entries shown first
PAGE_MORE = 20  # entries added by "Show 20 more"
LOG_SCAN_LINES = 500_000  # safety limit when looking for the latest status of devices


def _iter_log_lines_reverse(root, block_size=65536):
    """Yield lines of libreoxi.log from the newest to the oldest, reading the file backwards in blocks."""
    path = Path(root).expanduser().resolve() / "libreoxi.log"
    try:
        handle = path.open("rb")
    except OSError:
        return
    with handle:
        handle.seek(0, 2)
        position = handle.tell()
        remainder = b""
        while position > 0:
            size = min(block_size, position)
            position -= size
            handle.seek(position)
            chunk = handle.read(size) + remainder
            lines = chunk.split(b"\n")
            remainder = lines.pop(0)
            for line in reversed(lines):
                if line.strip():
                    yield line.decode("utf-8", errors="replace")
        if remainder.strip():
            yield remainder.decode("utf-8", errors="replace")


def _page_size(request, name):
    try:
        value = int(request.GET.get(name, PAGE_FIRST))
    except (TypeError, ValueError):
        value = PAGE_FIRST
    return max(PAGE_FIRST, min(value, 5000))


LOG_STATUSES = ("CHANGE", "NOCHANGE", "ERROR")


def read_device_logs(root, device, settings, limit=PAGE_FIRST, event=None):
    """Newest log entries of a device (optionally only one event type); returns (entries, has_more)."""
    needle = str(device)
    entries = []
    for line in _iter_log_lines_reverse(root):
        if needle not in line:
            continue
        parsed = _parse_log_line(line, settings)
        if parsed["device_name"] == needle and (not event or parsed["event"] == event):
            if len(entries) >= limit:
                return entries, True
            entries.append(parsed)
    return entries, False


def read_scheduler_logs(root, settings, limit=PAGE_FIRST):
    """Newest scheduled run summaries; returns (entries, has_more)."""
    entries = []
    for line in _iter_log_lines_reverse(root):
        if "scheduled refresh finished" not in line:
            continue
        parsed = _parse_log_line(line, settings)
        if parsed["event"] == "SCHEDULER" and parsed["run_summary"]:
            if len(entries) >= limit:
                return entries, True
            entries.append(parsed)
    return entries, False


def latest_device_logs(root, devices, settings):
    """Latest log entry of each given device in a single backwards pass over the log."""
    wanted = {str(device): device for device in devices}
    latest = {}
    for scanned, line in enumerate(_iter_log_lines_reverse(root)):
        if len(latest) == len(wanted) or scanned >= LOG_SCAN_LINES:
            break
        parts = line.split(" ", 2)
        if len(parts) < 2 or parts[1] not in ("CHANGE", "NOCHANGE", "ERROR"):
            continue
        parsed = _parse_log_line(line, settings)
        name = parsed["device_name"]
        if name in wanted and name not in latest:
            latest[name] = parsed
    return latest


def _history_path(settings, device, revision):
    if not revision or Path(revision).name != revision:
        return None
    directory = device_dir(settings.storage_root, device.pk, create=False)
    history = {p.name for p in list_history(settings.storage_root, device.pk)}
    return directory / revision if revision in history else None


def _revision_time(settings, device, revision):
    """UTC time of a stored revision (history files are named by their UTC timestamp)."""
    if revision == "current.cfg":
        path = device_dir(settings.storage_root, device.pk, create=False) / "current.cfg"
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.now(timezone.utc)
    try:
        return datetime.strptime(revision.removesuffix(".cfg"), "%Y-%m-%d_%H-%M-%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _load_revision(settings, device, revision):
    if revision == "current.cfg":
        return read_current(settings.storage_root, device.pk)
    path = _history_path(settings, device, revision)
    if path is None:
        return None, None
    return path.read_text(encoding="utf-8", errors="replace"), None


@register_model_view(Device, name="libreoxi", path="libreoxi")
class DeviceLibreOXIView(generic.ObjectView):
    queryset = Device.objects.all()
    tab = ViewTab(label="LibreOXI", weight=500)

    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        settings = LibreOXISettings.objects.first()
        current = current_hash = selected_config = None
        selected_name = "current.cfg"
        history = []
        monitored = False
        last_check = None
        storage_error = None
        device_logs = []
        logs_more = False
        if settings:
            monitored = monitored_devices(settings).filter(pk=device.pk).exists()
            try:
                current, current_hash = read_current(settings.storage_root, device.pk)
                directory = device_dir(settings.storage_root, device.pk, create=False)
                marker = directory / "last_check"
                if marker.exists():
                    last_check = format_timestamp(marker.read_text(encoding="utf-8").strip(), settings)
                history_paths = [p for p in list_history(settings.storage_root, device.pk) if p.name != "current.cfg"]
                history = [{"name": p.name, "display": format_revision(p.name, settings)} for p in history_paths]
                revision = request.GET.get("revision", "").strip()
                if revision and any(item["name"] == revision for item in history):
                    selected_config = (directory / revision).read_text(encoding="utf-8", errors="replace")
                    selected_name = revision
                else:
                    selected_config = current
                device_logs, logs_more = read_device_logs(settings.storage_root, device, settings, _page_size(request, "limit"))
            except OSError as exc:
                storage_error = f"LibreOXI storage: {exc}"
        return render(request, "netbox_libreoxi/device_tab.html", {
            "object": device, "device": device, "tab": self.tab, "settings": settings,
            "monitored": monitored, "current": current, "current_hash": current_hash,
            "selected_config": selected_config, "selected_name": selected_name, "history": history,
            "last_check": last_check, "storage_error": storage_error, "device_logs": device_logs,
            "logs_more": logs_more, "more_limit": _page_size(request, "limit") + PAGE_MORE,
            "lang": language_of(settings),
        })

    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        settings = LibreOXISettings.objects.first()
        if not settings:
            messages.error(request, tr("msg.not_configured", language_of(settings)))
        elif not monitored_devices(settings).filter(pk=device.pk).exists():
            messages.warning(request, tr("msg.not_monitored", language_of(settings)))
        else:
            result = fetch_device(settings, device)
            if result["ok"]:
                messages.warning(request, tr("msg.changed", language_of(settings))) if result["changed"] else messages.success(request, tr("msg.no_change", language_of(settings)))
            else:
                messages.error(request, tr("msg.not_changed_error", language_of(settings), error=result['error']))
        return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))


def compare_config(request, pk):
    device = get_object_or_404(Device, pk=pk)
    settings = LibreOXISettings.objects.first()
    if not settings or not monitored_devices(settings).filter(pk=device.pk).exists():
        return HttpResponse("Device is not selected for LibreOXI monitoring.", status=404, content_type="text/plain")
    old_name = request.GET.get("old", "").strip(); new_name = request.GET.get("new", "").strip()
    if not old_name or not new_name or old_name == new_name:
        return HttpResponse("Select two different configuration revisions.", status=400, content_type="text/plain")
    # Always compare the older revision against the newer one, regardless of the
    # order in which the revisions were selected. History filenames are UTC
    # timestamps (sortable as text) and current.cfg is always the newest.
    old_name, new_name = sorted((old_name, new_name), key=lambda name: (name == "current.cfg", name))
    try:
        old_content, _ = _load_revision(settings, device, old_name); new_content, _ = _load_revision(settings, device, new_name)
    except OSError as exc:
        return HttpResponse(f"LibreOXI storage is not accessible: {exc}", status=500, content_type="text/plain")
    if old_content is None or new_content is None:
        return HttpResponse("Configuration revision not found.", status=404, content_type="text/plain")
    old_lines = old_content.splitlines(); new_lines = new_content.splitlines(); matcher = SequenceMatcher(None, old_lines, new_lines)
    added = removed = changed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "insert": added += j2 - j1
        elif tag == "delete": removed += i2 - i1
        elif tag == "replace": removed += i2 - i1; added += j2 - j1; changed += 1
    fromdesc, todesc = format_revision(old_name, settings), format_revision(new_name, settings)
    html_diff = HtmlDiff(tabsize=4, wrapcolumn=140).make_table(old_lines, new_lines, fromdesc=fromdesc, todesc=todesc, context=True, numlines=3)
    full_diff = HtmlDiff(tabsize=4, wrapcolumn=140).make_table(old_lines, new_lines, fromdesc=fromdesc, todesc=todesc, context=False)
    lang = language_of(settings)
    html_diff = html_diff.replace("No Differences Found", tr("cmp.no_diff", lang)).replace("Empty File", tr("cmp.empty_file", lang))
    full_diff = full_diff.replace("No Differences Found", tr("cmp.no_diff", lang)).replace("Empty File", tr("cmp.empty_file", lang))
    changes = compare_changes(old_content, new_content)
    ip = str(device.primary_ip4.address.ip) if device.primary_ip4 else ""
    audit_report = audit.build_preview(
        settings, device, ip, changes, _revision_time(settings, device, old_name), _revision_time(settings, device, new_name),
        author=config_author(new_content),
    )
    audit_subject, _audit_text, audit_html = audit.render_report(settings, audit_report)
    return render(request, "netbox_libreoxi/compare.html", {"object": device, "device": device, "tab": DeviceLibreOXIView.tab, "old_name": old_name, "new_name": new_name, "added": added, "removed": removed, "changed": changed, "diff_html": mark_safe(html_diff), "full_diff_html": mark_safe(full_diff), "old_display": fromdesc, "new_display": todesc, "changes": audit.annotate(settings, changes), "change_counts": change_summary(changes), "audit_report": audit_report, "audit_subject": audit_subject, "audit_html": mark_safe(audit_html), "audit_min_severity": audit.severity_label(settings.audit_min_severity, language_of(settings)), "lang": language_of(settings)})


def delete_revision(request, pk):
    device = get_object_or_404(Device, pk=pk); settings = LibreOXISettings.objects.first()
    if request.method != "POST": return HttpResponse("POST required.", status=405, content_type="text/plain")
    if not settings or not monitored_devices(settings).filter(pk=device.pk).exists(): return HttpResponse("Device is not selected for LibreOXI monitoring.", status=404, content_type="text/plain")
    revision = request.POST.get("revision", "").strip()
    if revision in ("", "current.cfg"):
        messages.error(request, tr("msg.current_not_deletable", language_of(settings))); return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))
    path = _history_path(settings, device, revision)
    if path is None:
        messages.error(request, tr("msg.revision_not_found", language_of(settings))); return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))
    try: path.unlink(); messages.success(request, tr("msg.revision_deleted", language_of(settings), revision=revision))
    except OSError as exc: messages.error(request, tr("msg.revision_delete_failed", language_of(settings), error=exc))
    return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))


def download_config(request, pk):
    device = get_object_or_404(Device, pk=pk); settings = LibreOXISettings.objects.first()
    if not settings or not monitored_devices(settings).filter(pk=device.pk).exists(): return HttpResponse("Device is not selected for LibreOXI monitoring.", status=404, content_type="text/plain")
    try:
        directory = device_dir(settings.storage_root, device.pk, create=False); revision = request.GET.get("revision", "").strip()
        if revision:
            history = {p.name for p in list_history(settings.storage_root, device.pk)}
            if revision not in history or Path(revision).name != revision: return HttpResponse("Configuration revision not found.", status=404, content_type="text/plain")
            current = (directory / revision).read_text(encoding="utf-8", errors="replace")
        else: current, _ = read_current(settings.storage_root, device.pk)
    except OSError as exc: return HttpResponse(f"LibreOXI storage is not accessible: {exc}", status=500, content_type="text/plain")
    if not current: return HttpResponse("No configuration is stored for this device.", status=404, content_type="text/plain")
    ip = device.primary_ip4.address.ip if device.primary_ip4 else None; filename = f"{ip}.txt" if ip else f"device-{device.pk}.txt"
    response = HttpResponse(current, content_type="text/plain; charset=utf-8"); response["Content-Disposition"] = f'attachment; filename="{filename}"'; return response


def logs_view(request):
    settings = LibreOXISettings.objects.first()
    if not settings:
        return render(request, "netbox_libreoxi/logs.html", {"settings": None, "devices": [], "selected_device": None, "logs": [], "scheduled_runs": [], "lang": "en"})

    query = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip().upper()
    status = status if status in LOG_STATUSES else ""
    all_devices = monitored_devices(settings)
    if query:
        all_devices = all_devices.filter(name__icontains=query)
    device_limit = _page_size(request, "devices")

    # Latest status of every matching device (one backwards pass; the last scheduled
    # run normally contains all devices, so only the end of the log is read).
    candidates = list(all_devices)
    status_total = len(candidates)
    latest = latest_device_logs(settings.storage_root, candidates, settings)
    status_counts = {key: 0 for key in LOG_STATUSES}
    for device in candidates:
        device.latest_log = latest.get(str(device))
        if device.latest_log and device.latest_log["event"] in status_counts:
            status_counts[device.latest_log["event"]] += 1
    if status:
        candidates = [device for device in candidates if device.latest_log and device.latest_log["event"] == status]
    devices_more = len(candidates) > device_limit
    devices = candidates[:device_limit]

    limit = _page_size(request, "limit")
    selected_device = None
    logs, logs_more, scheduled_runs, runs_more = [], False, [], False
    selected_id = request.GET.get("device", "").strip()
    if selected_id.isdigit():
        selected_device = monitored_devices(settings).filter(pk=int(selected_id)).first()
    if selected_device:
        logs, logs_more = read_device_logs(settings.storage_root, selected_device, settings, limit, event=status or None)
    else:
        scheduled_runs, runs_more = read_scheduler_logs(settings.storage_root, settings, limit)

    def more_url(**changes):
        params = request.GET.copy()
        for key, value in changes.items():
            params[key] = value
        return f"?{params.urlencode()}"

    return render(request, "netbox_libreoxi/logs.html", {
        "settings": settings, "devices": devices, "selected_device": selected_device, "logs": logs,
        "scheduled_runs": scheduled_runs, "lang": language_of(settings), "query": query,
        "devices_more": devices_more, "devices_more_url": more_url(devices=device_limit + PAGE_MORE),
        "logs_more": logs_more or runs_more, "logs_more_url": more_url(limit=limit + PAGE_MORE),
        "device_limit": device_limit,
        "status": status,
        "status_counts": status_counts,
        "status_total": status_total,
        "filter_qs": f"q={quote(query)}" if query else "",
        "list_qs": "&".join(
            part for part in (
                f"q={quote(query)}" if query else "",
                f"status={status}" if status else "",
                f"devices={device_limit}" if device_limit != PAGE_FIRST else "",
            ) if part
        ),
    })


def settings_view(request):
    instance = LibreOXISettings.objects.first()
    if instance is None: instance = LibreOXISettings(librenms_url="", oxidized_path="/api/v0/oxidized/config", storage_root="/opt/libreoxi")
    if request.method == "POST":
        form = LibreOXISettingsForm(request.POST, instance=instance)
        if form.is_valid():
            saved = form.save(); messages.success(request, tr("set.saved", language_of(saved)))
            return redirect("plugins:netbox_libreoxi:settings")
    else: form = LibreOXISettingsForm(instance=instance)
    return render(request, "netbox_libreoxi/settings.html", {"form": form, "lang": language_of(instance)})


def _audit_period(request, settings):
    """Return (since, until, label) for the period selected on the Audit page (local time)."""
    from datetime import date, timedelta

    period = request.GET.get("period", "today")
    now = django_timezone.localtime()

    def local_midnight(day):
        return django_timezone.make_aware(datetime(day.year, day.month, day.day))

    def parse_day(value):
        try:
            return date.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    date_format = settings.datetime_format.split(" ")[0] if settings.datetime_format else "%d.%m.%Y"
    lang = language_of(settings)
    today = now.date()
    if period == "yesterday":
        day = today - timedelta(days=1)
        return local_midnight(day), local_midnight(today), tr("period.yesterday", lang, day=day.strftime(date_format))
    if period == "day":
        day = parse_day(request.GET.get("day")) or today
        return local_midnight(day), local_midnight(day + timedelta(days=1)), tr("period.day", lang, day=day.strftime(date_format))
    if period == "range":
        start = parse_day(request.GET.get("from")) or today
        end = parse_day(request.GET.get("to")) or today
        if end < start:
            start, end = end, start
        return local_midnight(start), local_midnight(end + timedelta(days=1)), tr("period.range", lang, start=start.strftime(date_format), end=end.strftime(date_format))
    if period == "last7":
        start = today - timedelta(days=6)
        return local_midnight(start), local_midnight(today + timedelta(days=1)), tr("period.last7", lang, start=start.strftime(date_format), end=today.strftime(date_format))
    if period == "all":
        return None, None, tr("period.all", lang)
    return local_midnight(today), local_midnight(today + timedelta(days=1)), tr("period.today", lang, day=today.strftime(date_format))


def _chosen_recipients(request, settings, lang):
    """Recipients ticked in a send dialog plus additional typed addresses; None (with a message) when invalid."""
    configured = audit.recipients(settings)
    chosen = [address for address in request.POST.getlist("to") if address in configured]
    try:
        extra = audit.parse_addresses(request.POST.get("to_extra", ""))
    except ValueError as exc:
        messages.error(request, tr("ui.invalid_address", lang, address=exc))
        return None
    to = chosen + [address for address in extra if address not in chosen]
    if not to:
        messages.error(request, tr("ui.no_recipient_selected", lang))
        return None
    return to


def audit_view(request):
    if not request.user.is_authenticated:
        return redirect(f"{reverse('login')}?next={request.path}")
    settings = LibreOXISettings.objects.first()
    if not settings:
        return render(request, "netbox_libreoxi/audit.html", {"settings": None, "lang": "en"})

    devices = list(monitored_devices(settings))
    selected_ids = [int(value) for value in request.GET.getlist("device") if value.isdigit()]
    if selected_ids:
        devices = [device for device in devices if device.pk in selected_ids]
    since, until, label = _audit_period(request, settings)
    lang = language_of(settings)
    if request.method == "POST" and request.POST.get("action") == "send_email":
        attach_pdf = request.POST.get("attach_pdf") == "on"
        protect = request.POST.get("pdf_protect") == "on"
        password = (request.POST.get("pdf_password") or settings.audit_pdf_password) if protect else ""
        if attach_pdf and protect and not password:
            messages.error(request, tr("form.err_pdf_password", lang))
            return redirect(f"{request.path}?{request.GET.urlencode()}")
        to = _chosen_recipients(request, settings, lang)
        if to is None:
            return redirect(f"{request.path}?{request.GET.urlencode()}")
        try:
            result = audit.send_audit(
                settings, devices, since, until, label, force=True, to=to, attach_pdf=attach_pdf, pdf_password=password,
            )
            if result["sent"]:
                messages.success(request, tr("ui.audit_sent", lang, period=label, recipients=", ".join(to)))
            else:
                messages.warning(request, result["reason"])
        except Exception as exc:
            messages.error(request, tr("ui.audit_send_failed", lang, error=exc))
        return redirect(f"{request.path}?{request.GET.urlencode()}")
    context = {
        "settings": settings,
        "all_devices": list(monitored_devices(settings)),
        "selected_ids": selected_ids,
        "period": request.GET.get("period", "today"),
        "day": request.GET.get("day", ""),
        "date_from": request.GET.get("from", ""),
        "date_to": request.GET.get("to", ""),
        "period_label": label,
        "generated": "generate" in request.GET or "export" in request.GET,
        "recipients": ", ".join(audit.recipients(settings)),
        "recipient_list": audit.recipients(settings),
        "pdf_password_set": bool(settings.audit_pdf_password),
        "lang": lang,
        "default_attach_pdf": settings.audit_email_attach_pdf,
        "min_severity": audit.severity_label(settings.audit_min_severity, lang),
    }
    if not context["generated"]:
        return render(request, "netbox_libreoxi/audit.html", context)

    report = audit.build_audit(settings, devices, since, until, label)
    subject, _text, html = audit.render_report(settings, report)

    export = request.GET.get("export")
    stamp = django_timezone.localtime().strftime("%Y-%m-%d_%H-%M")
    if export == "csv":
        response = HttpResponse(audit.report_csv(settings, report), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="libreoxi-audit_{stamp}.csv"'
        return response
    if export == "pdf":
        from .audit_pdf import build_pdf

        response = HttpResponse(build_pdf(settings, report, subject), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="libreoxi-audit_{stamp}.pdf"'
        return response
    if export == "html":
        response = HttpResponse(audit.html_document(settings, report), content_type="text/html; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="libreoxi-audit_{stamp}.html"'
        return response

    context.update({"report": report, "audit_subject": subject, "audit_html": mark_safe(html), "query": request.GET.urlencode()})
    return render(request, "netbox_libreoxi/audit.html", context)


def email_view(request):
    if not request.user.is_authenticated:
        return redirect(f"{reverse('login')}?next={request.path}")
    instance = LibreOXISettings.objects.first()
    if instance is None:
        messages.warning(request, tr("ui.save_settings_first", "en"))
        return redirect("plugins:netbox_libreoxi:settings")

    lang = language_of(instance)
    if request.method == "POST" and request.POST.get("action") == "test_email":
        to = _chosen_recipients(request, instance, lang)
        if to is None:
            return redirect("plugins:netbox_libreoxi:email")
        try:
            audit.send_test_email(instance, to=to)
            messages.success(request, tr("ui.test_sent", lang, recipients=", ".join(to)))
        except Exception as exc:
            messages.error(request, tr("ui.test_failed", lang, error=exc))
        return redirect("plugins:netbox_libreoxi:email")

    if request.method == "POST":
        form = LibreOXIEmailForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, tr("ui.email_saved", lang))
            return redirect("plugins:netbox_libreoxi:email")
    else:
        form = LibreOXIEmailForm(instance=instance)
    last_sent = audit.read_last_sent(instance)
    return render(
        request,
        "netbox_libreoxi/email.html",
        {
            "form": form,
            "recipients": ", ".join(audit.recipients(instance)),
            "last_sent": format_timestamp(last_sent.isoformat(), instance) if last_sent else "",
            "password_set": bool(instance.smtp_password),
            "recipient_list": audit.recipients(instance),
            "pdf_password_set": bool(instance.audit_pdf_password),
            "lang": lang,
        },
    )



# --------------------------------------------------------------------------
# NetBox Self audit
# --------------------------------------------------------------------------

def self_settings_view(request):
    if not request.user.is_authenticated:
        return redirect(f"{reverse('login')}?next={request.path}")
    settings = LibreOXISettings.objects.first()
    if settings is None:
        messages.warning(request, tr("ui.save_settings_first", "en"))
        return redirect("plugins:netbox_libreoxi:settings")
    lang = language_of(settings)
    here = reverse("plugins:netbox_libreoxi:self_settings")

    if request.method == "POST" and request.POST.get("action") == "options":
        severity = request.POST.get("self_audit_min_severity", "low")
        settings.self_audit_min_severity = severity if severity in audit.SEVERITY_RANK else "low"
        settings.self_audit_email = request.POST.get("self_audit_email") == "on"
        settings.save(update_fields=["self_audit_min_severity", "self_audit_email"])
        messages.success(request, tr("self.options_saved", lang))
        return redirect(f"{here}?type={quote(request.POST.get('type', ''))}")

    if request.method == "POST" and request.POST.get("action") == "rules":
        key = request.POST.get("type", "")
        if self_audit.model_for(key) is None:
            messages.error(request, tr("self.unknown_type", lang))
            return redirect(here)
        existing = {rule.field: rule for rule in SelfAuditRule.objects.filter(object_type=key)}
        keys = list(self_audit.EVENTS) + [name for name, _label, _kind in self_audit.discover_fields(key)]
        watched = 0
        for field in keys:
            rule = existing.get(field)
            if request.POST.get(f"watch__{field}") != "on":
                if rule is not None:
                    rule.delete()
                continue
            severity = request.POST.get(f"sev__{field}", "medium")
            values = {
                "severity": severity if severity in audit.SEVERITY_RANK else "medium",
                "message": (request.POST.get(f"msg__{field}") or "").strip(),
                "enabled": True,
            }
            SelfAuditRule.objects.update_or_create(object_type=key, field=field, defaults=values)
            watched += 1
        messages.success(request, tr("self.rules_saved", lang, type=self_audit.type_label(key), count=watched))
        return redirect(f"{here}?type={quote(key)}")

    selected = request.GET.get("type", "")
    rows = []
    if selected and self_audit.model_for(selected) is not None:
        rules = {rule.field: rule for rule in SelfAuditRule.objects.filter(object_type=selected)}
        sections = [(tr("self.events", lang), [(field, self_audit.field_label(selected, field, lang), "event") for field in self_audit.EVENTS])]
        sections.extend(self_audit.field_sections(selected, lang))
        for title, items in sections:
            if not items:
                continue
            rows.append({"section": title})
            for field, label, kind in items:
                rule = rules.get(field)
                rows.append({
                    "field": field,
                    "label": label,
                    "kind": kind,
                    "watched": rule is not None,
                    "severity": rule.severity if rule else ("high" if kind == "event" else "medium"),
                    "message": rule.message if rule else "",
                    "default": tr(self_audit.default_message(field), lang),
                })
    elif selected:
        selected = ""

    by_type: dict[str, dict] = {}
    for rule in SelfAuditRule.objects.all():
        by_type.setdefault(rule.object_type, {})[rule.field] = rule
    overview = []
    for key, type_rules in by_type.items():
        order = list(self_audit.EVENTS) + [name for name, _label, _kind in self_audit.discover_fields(key)]
        fields = sorted(type_rules, key=lambda field: order.index(field) if field in order else len(order))
        overview.append({
            "key": key,
            "label": self_audit.type_label(key),
            "count": len(type_rules),
            "rules": [
                {
                    "label": self_audit.field_label(key, field, lang),
                    "severity": type_rules[field].severity,
                    "severity_label": audit.severity_label(type_rules[field].severity, lang),
                }
                for field in fields
            ],
        })
    overview.sort(key=lambda item: item["label"].lower())
    watched_types = [(item["key"], item["label"], item["count"]) for item in overview]
    return render(request, "netbox_libreoxi/self_settings.html", {
        "settings": settings,
        "lang": lang,
        "groups": self_audit.watchable_types(),
        "selected": selected,
        "selected_label": self_audit.type_label(selected) if selected else "",
        "rows": rows,
        "watched_types": watched_types,
        "overview": overview,
        "unsaved_text": mark_safe(json.dumps(tr("self.unsaved", lang))),
        "severities": audit.severities(lang),
        "placeholders": ", ".join("{" + name + "}" for name in self_audit.PLACEHOLDERS),
    })


def self_audit_view(request):
    if not request.user.is_authenticated:
        return redirect(f"{reverse('login')}?next={request.path}")
    settings = LibreOXISettings.objects.first()
    if not settings:
        return render(request, "netbox_libreoxi/self_audit.html", {"settings": None, "lang": "en"})
    lang = language_of(settings)
    since, until, label = _audit_period(request, settings)
    types = [key for key in request.GET.getlist("type") if key]
    min_severity = request.GET.get("severity") or settings.self_audit_min_severity
    if min_severity not in audit.SEVERITY_RANK:
        min_severity = "low"

    if request.method == "POST" and request.POST.get("action") == "send_email":
        attach_pdf = request.POST.get("attach_pdf") == "on"
        protect = request.POST.get("pdf_protect") == "on"
        password = (request.POST.get("pdf_password") or settings.audit_pdf_password) if protect else ""
        if attach_pdf and protect and not password:
            messages.error(request, tr("form.err_pdf_password", lang))
            return redirect(f"{request.path}?{request.GET.urlencode()}")
        to = _chosen_recipients(request, settings, lang)
        if to is None:
            return redirect(f"{request.path}?{request.GET.urlencode()}")
        try:
            result = self_audit.send_report(
                settings, since, until, label, to=to, force=True, attach_pdf=attach_pdf, pdf_password=password,
                types=types or None, min_severity=min_severity,
            )
            if result["sent"]:
                messages.success(request, tr("self.sent", lang, period=label, recipients=", ".join(to)))
            else:
                messages.warning(request, result["reason"])
        except Exception as exc:
            messages.error(request, tr("ui.audit_send_failed", lang, error=exc))
        return redirect(f"{request.path}?{request.GET.urlencode()}")

    watched = sorted({rule.object_type for rule in SelfAuditRule.objects.filter(enabled=True)})
    context = {
        "settings": settings,
        "lang": lang,
        "period": request.GET.get("period", "today"),
        "day": request.GET.get("day", ""),
        "date_from": request.GET.get("from", ""),
        "date_to": request.GET.get("to", ""),
        "period_label": label,
        "type_choices": [(key, self_audit.type_label(key)) for key in watched] + [("netbox.system", tr("self.system_type", lang))],
        "selected_types": types,
        "severities": audit.severities(lang),
        "min_severity": min_severity,
        "min_severity_label": audit.severity_label(min_severity, lang),
        "has_rules": bool(watched),
        "generated": "generate" in request.GET or "export" in request.GET,
        "recipients": ", ".join(audit.recipients(settings)),
        "recipient_list": audit.recipients(settings),
        "pdf_password_set": bool(settings.audit_pdf_password),
        "default_attach_pdf": settings.audit_email_attach_pdf,
    }
    if not context["generated"]:
        return render(request, "netbox_libreoxi/self_audit.html", context)

    report = self_audit.build_report(settings, since, until, label, types or None, min_severity)
    subject, _text, html = self_audit.render_report(settings, report)
    for entry in report["entries"]:
        entry["when_display"] = format_timestamp(entry["when"].isoformat(), settings)
    export = request.GET.get("export")
    stamp = django_timezone.localtime().strftime("%Y-%m-%d_%H-%M")
    if export == "csv":
        response = HttpResponse(self_audit.report_csv(settings, report), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="netbox-self-audit_{stamp}.csv"'
        return response
    if export == "pdf":
        from .audit_pdf import build_self_pdf

        response = HttpResponse(build_self_pdf(settings, report, subject), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="netbox-self-audit_{stamp}.pdf"'
        return response
    if export == "html":
        response = HttpResponse(self_audit.html_document(settings, report), content_type="text/html; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="netbox-self-audit_{stamp}.html"'
        return response

    context.update({"report": report, "subject": subject, "query": request.GET.urlencode()})
    return render(request, "netbox_libreoxi/self_audit.html", context)
