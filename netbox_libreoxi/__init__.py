from netbox.plugins import PluginConfig


class NetBoxLibreOXIConfig(PluginConfig):
    name = "netbox_libreoxi"
    verbose_name = "NetBox LibreOXI"
    description = "Retrieve and track network device configurations from LibreNMS Oxidized/OXI."
    version = "1.0.1"
    base_url = "libreoxi"
    min_version = "4.7.0"
    max_version = "4.7.99"
    default_settings = {
        "storage_root": "/var/lib/netbox/libreoxi",
        "request_timeout": 10,
        "check_interval_minutes": 5,
        "schedule_cron": "*/5 * * * *",
        "retention_days": 365,
        "retention_revisions": 100,
        "verify_tls": True,
    }
    menu = "navigation.menu"

    def ready(self):
        super().ready()
        from .jobs import libreoxi  # noqa: F401


config = NetBoxLibreOXIConfig
