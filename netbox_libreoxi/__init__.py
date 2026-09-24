from netbox.plugins import PluginConfig


class NetBoxLibreOXIConfig(PluginConfig):
    name = "netbox_libreoxi"
    verbose_name = "NetBox LibreOXI"
    description = "Retrieve and track network device configurations from LibreNMS Oxidized/OXI."
    version = "0.1.0"
    base_url = "libreoxi"
    min_version = "6.0.0"
    max_version = "6.9.99"
    default_settings = {
        "storage_root": "/var/lib/netbox/libreoxi",
        "request_timeout": 10,
        "check_interval_minutes": 60,
        "retention_days": 365,
        "retention_revisions": 100,
        "verify_tls": True,
    }


config = NetBoxLibreOXIConfig
