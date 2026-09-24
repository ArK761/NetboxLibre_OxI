from django.urls import path

from . import views

app_name = "netbox_libreoxi"

urlpatterns = [
    path("settings/", views.settings_view, name="settings"),
    path("devices/<int:pk>/download/", views.download_config, name="download_config"),
]
