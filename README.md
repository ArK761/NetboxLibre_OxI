# NetBox LibreOXI

NetBox plugin for monitoring and storing network device configurations retrieved from LibreNMS Oxidized/OXI.

## Installation / upgrade

Install or upgrade the plugin with the standard pip command:

```bash
pip install --upgrade --force-reinstall git+https://github.com/ArK761/NetboxLibre_OxI.git
```

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

Restart the NetBox service after installation or upgrade:

```bash
systemctl restart netbox.service
```

The default LibreOXI storage path is `/opt/libreoxi`.

### Upgrade

For a later plugin upgrade, use the same pip command:

```bash
pip install --upgrade --force-reinstall git+https://github.com/ArK761/NetboxLibre_OxI.git
```

If the release contains new database migrations, run:

```bash
cd /opt/netbox/netbox
./manage.py migrate netbox_libreoxi
```

Then restart NetBox:

```bash
systemctl restart netbox.service
```

## Features

### Configuration snapshots and history

- LibreNMS/OXI is the configuration source.
- Configuration is retrieved through the LibreNMS API.
- The API JSON response is parsed and only the `config` content is stored as the device configuration.
- The NetBox database stores plugin settings and metadata only.
- Configuration files, SHA-256 hashes and revision history are stored on the filesystem.
- A failed, invalid or empty API response must never overwrite the last valid configuration.
- If the configuration hash is unchanged, no new revision is created.
- If the hash changes, the new configuration is stored as a timestamped snapshot and becomes the current configuration.
- History retention is controlled by age and maximum revision count.
- Device pages provide a LibreOXI tab and a manual Refresh action.
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

The generic diff is intentionally vendor-neutral. Vendor-specific semantic analysis (for example, identifying a VLAN addition or an interface-name change) can be added later as an optional analyzer without changing the underlying snapshot history.

### Monitoring and refresh

- Automatic checks run asynchronously.
- Monitoring can be restricted by Device Role and/or explicitly selected devices.
- Plugin settings are editable through the NetBox web UI and take effect without restarting NetBox.

## Initial design

- LibreNMS/OXI is the configuration source.
- The NetBox database stores plugin settings and metadata only.
- Configuration files, SHA-256 hashes and revision history are stored on the filesystem.
- A failed or invalid API response must never overwrite the last valid configuration.
- Automatic checks run asynchronously.
- Device pages provide a LibreOXI tab and a manual Refresh action.
- If the configuration hash is unchanged, no new revision is created.
- If the hash changes, the new configuration is stored and compared with the previous revision.
- History retention is controlled by age and maximum revision count.
- Plugin settings are editable through the NetBox web UI and take effect without restarting NetBox.

## Planned structure

```
netbox_libreoxi/
  api/
  jobs/
  storage/
  models/
  views/
  templates/
  migrations/
tests/
```
