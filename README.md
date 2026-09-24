# NetBox LibreOXI

NetBox plugin for monitoring and storing network device configurations retrieved from LibreNMS Oxidized/OXI.

## Installation / upgrade

The plugin itself is installed or upgraded using the standard pip command:

```bash
pip install --upgrade --force-reinstall git+https://github.com/ArK761/NetboxLibre_OxI.git
```

LibreOXI also requires a filesystem storage directory. Run the repository installer once on the NetBox server to create it with the correct ownership and permissions and to run the plugin migrations:

```bash
sudo ./scripts/install.sh
```

The installer creates:

```text
/opt/libreoxi
owner: netbox:netbox
mode: 750
```

The installer uses the same pip install/upgrade command shown above, then runs:

```bash
/opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_libreoxi --no-input
```

### Manual installation

When the storage directory has already been created, the plugin can be installed or upgraded directly with:

```bash
pip install --upgrade --force-reinstall git+https://github.com/ArK761/NetboxLibre_OxI.git
```

Then run the LibreOXI migration:

```bash
cd /opt/netbox/netbox
./manage.py migrate netbox_libreoxi
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
scripts/
  install.sh
```
