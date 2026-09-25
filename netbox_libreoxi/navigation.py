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
)

logs_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:logs",
    link_text=menu_label("menu.logs"),
)

audit_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:audit",
    link_text=menu_label("menu.audit"),
)

email_item = PluginMenuItem(
    link="plugins:netbox_libreoxi:email",
    link_text=menu_label("menu.email"),
)


menu = PluginMenu(
    label="LibreOXI",
    groups=(
        ("LibreOXI", (settings_item, logs_item, audit_item, email_item)),
    ),
    icon_class="mdi mdi-content-save-cog",
)

menu_items = (settings_item, logs_item, audit_item, email_item)
