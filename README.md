# NetBox LibreOXI

NetBox plugin for monitoring and storing network device configurations retrieved from LibreNMS Oxidized/OXI.

## Installation / upgrade

Install or upgrade the plugin with the standard pip command:

```bash
pip install --upgrade --force-reinstall git+https://github.com/ArK761/NetboxLibre_OxI.git@1.0.1
```

Without `@<version>` pip installs the latest code from the `main` branch. To return to an older release use its tag,
e.g. `...NetboxLibre_OxI.git@1.0.0`.

After installing the plugin, create the LibreOXI filesystem storage directory manually on the NetBox server. The NetBox service user must own the directory because the plugin writes configurations, hashes, history and logs there.

```bash
mkdir -p /opt/libreoxi
chown netbox:netbox /opt/libreoxi
chmod 750 /opt/libreoxi
```

Then run the plugin migration:

```bash
cd /opt/netbox/netbox
./manage.py migrate netbox_libreoxi
```

Restart NetBox and its background worker after installation or upgrade:

```bash
systemctl restart netbox netbox-rq
```

The default LibreOXI storage path is `/opt/libreoxi`.

### Upgrade

For a later plugin upgrade, use the same pip command. If the release contains new database migrations, run the migration command shown above and restart NetBox.

## Features

### Configuration snapshots and history

- LibreNMS/OXI is the configuration source.
- Configuration is retrieved through the LibreNMS API using the device primary IPv4 address.
- The API JSON response is parsed and only the `config` content is stored as the device configuration.
- The NetBox database stores plugin settings and metadata only.
- Configuration files, SHA-256 hashes, history and logs are stored on the filesystem.
- A failed, invalid or empty API response must never overwrite the last valid configuration.
- If the configuration hash is unchanged, no new revision is created.
- If the hash changes, the new configuration is stored as a timestamped snapshot and becomes the current configuration.
- History retention is controlled by age and maximum revision count.
- Device pages provide a LibreOXI tab and a manual Refresh action.
- Manual Refresh is allowed only for devices selected by Device Role or explicitly selected as an individual device in LibreOXI Settings.
- The same monitoring scope is enforced by the backend for scheduled and manual configuration retrieval.
- The device page can display the current configuration or any stored historical revision.
- A selected configuration can be copied to the clipboard or downloaded as `<device-IP>.txt`.
- Historical revisions can be deleted individually; the current configuration cannot be deleted from the history view.

### Configuration comparison / audit

LibreOXI includes a vendor-neutral configuration comparison based on Python's standard-library `difflib`.

Two stored configurations can be selected and compared directly from the device's LibreOXI tab. The comparison works with plain text configuration files and therefore does not depend on a particular network-vendor syntax.

The comparison provides:

- side-by-side HTML diff;
- added and removed lines highlighted;
- changed lines highlighted within the comparison;
- comparison of any two historical revisions;
- comparison between a historical revision and the current configuration;
- a simple summary of added/removed/changed content;
- the original configuration snapshots remain unchanged by the comparison.

#### Detected changes (semantic summary)

Above the line-by-line diff, the comparison page lists the changes in human-readable form, for example:

- `Interface GigabitEthernet1/0/5: access VLAN changed "10" -> "20"`
- `VLAN 10: name changed "Users" -> "Staff"`
- `Interface Gi1/0/1: description changed "Uplink" -> "Uplink to core-2"`
- `Interface Gi1/0/6: administratively disabled (shutdown)`
- `VLAN 30 added (name Guests)`
- `Hostname changed "SW1" -> "SW2"`
- `Port ether2: native VLAN (PVID) changed "10" -> "40"`
- `Port ether5 was added (bridge bridge1, PVID 40)`
- `VLAN interface vlan40: IP address added "10.40.0.1/24"`
- `Firmware (RouterOS) changed from "7.14.2" to "7.15.1"`

The configuration is parsed into sections without any external dependency, so it works across vendors:
indentation-based configurations (Cisco IOS/NX-OS, Arista, HP/Aruba incl. Aruba Instant On 1930, Dell OS10,
Allied Telesis AlliedWare Plus, Ubiquiti EdgeSwitch, Fortinet), brace-based configurations (Juniper Junos, VyOS),
`set`-style configurations (Junos/VyOS display set), MikroTik RouterOS exports and pfSense/OPNsense `config.xml`
(firewall rules, NAT, aliases, users, interfaces, VLANs, SNMP, web GUI). For pfSense the
audit also shows who saved the configuration (from `<revision>`).
Changes that only reorder lines or change comments/timestamps are ignored.

#### Firmware / OS version

The firmware or OS version is read from the header Oxidized adds to the configuration (pfSense/OPNsense
`<!-- PFsense 26.03-RELEASE -->`, MikroTik `installed-version` / `by RouterOS`, RouterBOOT, Aruba Instant On,
FortiOS, ProCurve/ArubaOS, EdgeSwitch, AlliedWare Plus, Dell OS10 `Software version`, Cisco IOS `Image: Software`,
Junos). A version change is reported as its own change and audit category (Critical by default).
A generic "software/firmware version" line is used only when no vendor-specific version is found.

#### Audit for the security manager

Every detected change is assigned an audit category and a severity:

| Category | Default severity |
|---|---|
| Firmware / OS version | Critical |
| Firewall / ACL / VPN (rules, NAT, aliases, VPN) | Critical |
| Users and access (users, passwords, AAA) | Critical |
| Device management (SNMP, SSH/HTTP, logging, NTP, management VLAN) | High |
| Routing (static routes, OSPF, BGP, gateway, interface IP addresses) | High |
| VLANs (added/removed VLANs, port VLANs) | Medium |
| Ports (shutdown/no shutdown, port security) | Medium |
| Descriptions and names | Low |
| Other changes | Low |

The **LibreOXI → Audit** page generates the audit for all monitored devices at once (or selected devices)
for today, yesterday, the last 7 days, a specific day, a date range or the complete stored history. It is built
from the stored configuration history by comparing consecutive revisions, so it also covers changes made before
the audit feature was installed (within the configured retention). The report can be downloaded as **PDF**,
**CSV** (Excel) or **HTML** and sent by e-mail from the Audit page (**Send by e-mail**).

**Automatic audit e-mail** (separate page **LibreOXI → E-mail**):

- recipients: one or more addresses (a group address works too);
- frequency: daily (previous day), weekly (last 7 days, on a chosen weekday) or monthly (previous month, on the 1st);
- send time, optional e-mail when there were no changes, optional PDF attachment, optionally protected with a password
  (the audit is always in the e-mail body);
- Email Options like in LibreNMS: from name, from address, SMTP server, port, timeout, encryption
  (Disabled / SSL / TLS-STARTTLS), Auto TLS and optional SMTP authentication. The plugin talks to the SMTP server
  directly, independently of NetBox's own e-mail configuration. When the SMTP server is empty, NetBox's `EMAIL`
  settings from `configuration.py` are used;
- **Send test e-mail** sends a test e-mail using the saved settings (save the settings first); the recipients are
  chosen in a dialog.

The e-mail is sent by the NetBox background worker (`netbox-rq`); results are written to the LibreOXI log.
PDF generation uses `reportlab` (installed automatically) and the bundled DejaVu Sans font (see `fonts/LICENSE-DejaVu.txt`).

**Language:** LibreOXI Settings → *Language* selects English (default), Slovak, Czech or German for the whole
plugin UI (menu, Settings, Logs, device tab, compare, Audit and E-mail pages) and for the audit (e-mail, PDF, CSV,
preview). Log files are always written in English.

When sending an audit from the Audit page, a dialog asks for the recipients (ticked from the configured list and/or
other addresses), whether to attach the PDF and whether to protect it with a password. PDF is the only attachment type.

The audit describes changes in plain language, e.g.
`VLAN 201 "## TEST ##" was added (on bridge1, tagged on ports sfp-sfpplus2, sfp-sfpplus1).`

Severities, the minimum severity reported to the security manager and the fields included in the
report are configured in LibreOXI Settings. The compare page shows an **Audit preview** of exactly
what would be sent.

### Passwords and secrets

- Passwords, secrets, keys, pre-shared keys and SNMP communities are masked in the compare summary, audit, PDF and
  e-mail — the audit only says that a password/secret was changed.
- pfSense/OPNsense XML secrets are compared by fingerprint; the value is never displayed.
- The SMTP password and PDF password fields are not shown back in the form after saving.
- The LibreNMS API token, SMTP password and PDF password are stored in the NetBox database **as plain text**
  (not encrypted). Restrict access to the NetBox database and its backups accordingly.
- A password-protected PDF uses 128-bit encryption; printing and copying text are allowed, editing is blocked.

### Monitoring, refresh and audit logs

- Automatic checks run asynchronously according to the configured check interval.
- The scheduler wakes periodically, but the configured `Check interval minutes` determines when a real device refresh is performed.
- Scheduled refresh checks use a maximum of **5 concurrent device checks**. With 200 monitored devices, five LibreNMS API requests can therefore run at the same time instead of checking all devices sequentially.
- Monitoring can be restricted by Device Role and/or explicitly selected devices.
- Every attempted device check is written to the LibreOXI log, including successful checks where no configuration change was detected.
- Configuration changes are logged with the device and resulting SHA-256 hash.
- The device's LibreOXI tab displays recent activity for that device.
- The device page shows the next scheduled check time and a live countdown when the scheduler has completed at least one scheduled refresh.
- The LibreOXI main menu contains a global Logs page showing checks and configuration changes across all monitored devices.
- Logs and configuration history are stored on the configured filesystem storage root.
- Log rows keep the SHA-256 available behind an expandable details control while keeping the normal audit view compact.
- The Logs page shows the latest status of every device (change / no change / error) with counts, can be filtered by
  status and searched, and pages the device list (latest 10, then 20 more).
- Log files are read backwards, so the page stays fast even with large log files.

### Date/time display format

LibreOXI stores timestamps internally in UTC/ISO form. The Settings page provides a selectable display format so the same stored timestamps can be shown in a preferred format without changing the stored data.

Available formats include:

- `24.09.2026 18:06:06` (EU);
- `24/09/2026 18:06:06` (EU slash);
- `2026-09-24 18:06:06` (ISO-like);
- `24.09.2026 18:06` (EU without seconds);
- `2026-09-24T18:06:06` (ISO 8601).

The selected display format applies to device check times, configuration history timestamps, and LibreOXI logs. It does not alter timestamps stored internally or configuration snapshot filenames.

### Settings and storage

- Plugin settings are editable through the NetBox web UI.
- The configured storage path is validated when settings are saved: it must exist, be a directory, and be writable by the NetBox process.
- A real temporary file write/delete test is performed during validation.
- The configured storage path is used immediately by device views and scheduled refresh jobs.
