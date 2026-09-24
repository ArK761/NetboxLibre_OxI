from netbox.plugins import PluginMenu, PluginMenuItem


settings_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:settings",
    link_text="Settings",
)


menu = PluginMenu(
    label="LibreOXI",
    groups=(
        ("LibreOXI", (settings_item,)),
    ),
    icon_class="mdi mdi-content-save-cog",
)

menu_items = (settings_item,)
