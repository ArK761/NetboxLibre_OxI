from netbox.plugins import PluginMenu, PluginMenuItem


settings_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:settings",
    link_text="Settings",
)

logs_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:logs",
    link_text="Logs",
)

audit_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:audit",
    link_text="Audit",
)


menu = PluginMenu(
    label="LibreOXI",
    groups=(
        ("LibreOXI", (settings_item, logs_item, audit_item)),
    ),
    icon_class="mdi mdi-content-save-cog",
)

menu_items = (settings_item, logs_item, audit_item)
