# NetBox LibreOXI

NetBox plugin for monitoring and storing network device configurations retrieved from LibreNMS Oxidized/OXI.

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

This repository is an initial design/skeleton and will be implemented incrementally.
