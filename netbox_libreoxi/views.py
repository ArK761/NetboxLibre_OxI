from datetime import datetime, timezone
from pathlib import Path
from difflib import HtmlDiff, SequenceMatcher

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.utils import timezone as django_timezone
from django.utils.safestring import mark_safe

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from . import audit
from .config_changes import compare as compare_changes, config_author, summary as change_summary
from .forms import LibreOXIEmailForm, LibreOXISettingsForm
from .i18n import language_of, tr
from .models import LibreOXISettings
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


def _read_log_lines(root):
    path = Path(root).expanduser().resolve() / "libreoxi.log"
    if not path.exists():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def read_device_logs(root, device, settings, limit=100):
    needle = str(device)
    entries = []
    for line in reversed(_read_log_lines(root)):
        parsed = _parse_log_line(line, settings)
        if parsed["device_name"] == needle:
            entries.append(parsed)
            if len(entries) >= limit:
                break
    return entries


def read_scheduler_logs(root, settings, limit=100):
    entries = []
    for line in reversed(_read_log_lines(root)):
        parsed = _parse_log_line(line, settings)
        if parsed["event"] == "SCHEDULER" and parsed["run_summary"]:
            entries.append(parsed)
            if len(entries) >= limit:
                break
    return entries


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
                device_logs = read_device_logs(settings.storage_root, device, settings)
            except OSError as exc:
                storage_error = f"LibreOXI storage is not accessible: {exc}"
        return render(request, "netbox_libreoxi/device_tab.html", {
            "object": device, "device": device, "tab": self.tab, "settings": settings,
            "monitored": monitored, "current": current, "current_hash": current_hash,
            "selected_config": selected_config, "selected_name": selected_name, "history": history,
            "last_check": last_check, "storage_error": storage_error, "device_logs": device_logs,
        })

    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        settings = LibreOXISettings.objects.first()
        if not settings:
            messages.error(request, "LibreOXI settings have not been configured.")
        elif not monitored_devices(settings).filter(pk=device.pk).exists():
            messages.warning(request, "This device is not selected for LibreOXI monitoring.")
        else:
            result = fetch_device(settings, device)
            if result["ok"]:
                messages.warning(request, "Configuration changed and a new revision was stored.") if result["changed"] else messages.success(request, "No configuration change detected.")
            else:
                messages.error(request, f"Configuration was not changed: {result['error']}")
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
        messages.error(request, "The current configuration cannot be deleted."); return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))
    path = _history_path(settings, device, revision)
    if path is None:
        messages.error(request, "Configuration revision not found."); return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))
    try: path.unlink(); messages.success(request, f"Configuration revision {revision} was deleted.")
    except OSError as exc: messages.error(request, f"Configuration revision could not be deleted: {exc}")
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
        return render(request, "netbox_libreoxi/logs.html", {"settings": None, "devices": [], "selected_device": None, "logs": [], "scheduled_runs": []})
    devices = list(monitored_devices(settings)); selected_id = request.GET.get("device", "").strip(); selected_device = None; logs = []
    if selected_id.isdigit():
        selected_device = next((device for device in devices if device.pk == int(selected_id)), None)
        if selected_device: logs = read_device_logs(settings.storage_root, selected_device, settings)
    for device in devices:
        device_logs = read_device_logs(settings.storage_root, device, settings, limit=1); device.latest_log = device_logs[0] if device_logs else None
    scheduled_runs = read_scheduler_logs(settings.storage_root, settings)
    return render(request, "netbox_libreoxi/logs.html", {"settings": settings, "devices": devices, "selected_device": selected_device, "logs": logs, "scheduled_runs": scheduled_runs})


def settings_view(request):
    instance = LibreOXISettings.objects.first()
    if instance is None: instance = LibreOXISettings(librenms_url="", oxidized_path="/api/v0/oxidized/config", storage_root="/opt/libreoxi")
    if request.method == "POST":
        form = LibreOXISettingsForm(request.POST, instance=instance)
        if form.is_valid():
            form.save(); messages.success(request, "LibreOXI settings saved. New storage path is used immediately by device views and refresh jobs.")
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


def audit_view(request):
    if not request.user.is_authenticated:
        return redirect(f"{reverse('login')}?next={request.path}")
    settings = LibreOXISettings.objects.first()
    if not settings:
        return render(request, "netbox_libreoxi/audit.html", {"settings": None})

    devices = list(monitored_devices(settings))
    selected_ids = [int(value) for value in request.GET.getlist("device") if value.isdigit()]
    if selected_ids:
        devices = [device for device in devices if device.pk in selected_ids]
    since, until, label = _audit_period(request, settings)
    lang = language_of(settings)
    if request.method == "POST" and request.POST.get("action") == "send_email":
        attachments = [kind for kind in request.POST.getlist("attach") if kind in ("pdf", "csv", "html")]
        try:
            result = audit.send_audit(settings, devices, since, until, label, force=True, attachments=attachments)
            if result["sent"]:
                messages.success(request, tr("ui.audit_sent", lang, period=label, recipients=", ".join(audit.recipients(settings))))
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
        "lang": lang,
        "default_attach_pdf": settings.audit_email_attach_pdf,
        "default_attach_csv": settings.audit_email_attach_csv,
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
        try:
            audit.send_test_email(instance)
            messages.success(request, tr("ui.test_sent", lang, recipients=", ".join(audit.recipients(instance))))
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
            "lang": lang,
        },
    )

