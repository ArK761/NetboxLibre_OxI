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

## Initial design

- LibreNMS/OXI is the configuration source.
- Configuration is retrieved through the LibreNMS API.
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
