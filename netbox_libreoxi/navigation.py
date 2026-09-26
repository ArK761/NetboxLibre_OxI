from django.utils.functional import lazy

from netbox.plugins import PluginMenu, PluginMenuItem


def _menu_label(key: str) -> str:
    """Menu label in the language chosen in LibreOXI Settings (evaluated at render time)."""
    from .i18n import language_of, tr

    try:
        from .models import LibreOXISettings

        lang = language_of(LibreOXISettings.objects.first())
    except Exception:  # database not ready (migrations, startup)
        lang = "en"
    return tr(key, lang)


menu_label = lazy(_menu_label, str)


settings_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:settings",
    link_text=menu_label("menu.settings"),
    permissions=["netbox_libreoxi.change_libreoxisettings"],
)

logs_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:logs",
    link_text=menu_label("menu.logs"),
    permissions=["netbox_libreoxi.view_libreoxisettings"],
)

audit_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:audit",
    link_text=menu_label("menu.audit"),
    permissions=["netbox_libreoxi.view_libreoxisettings"],
)

email_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:email",
    link_text=menu_label("menu.email"),
    permissions=["netbox_libreoxi.change_libreoxisettings"],
)


menu = PluginMenu(
    label="LibreOXI",
    groups=(
        ("LibreOXI", (settings_item, logs_item, audit_item, email_item)),
    ),
    icon_class="mdi mdi-content-save-cog",
)

# Only an own top-level menu. NetBox also reads a module-level "menu_items" and would list the same
# items a second time under "Plugins", so that name must not be defined here.
