from django.urls import path

from . import views

app_name = "netbox_libreoxi"

urlpatterns = [
    path("settings/", views.settings_view, name="settings"),
    path("logs/", views.logs_view, name="logs"),
    path("audit/", views.audit_view, name="audit"),
    path("email/", views.email_view, name="email"),
    path("devices/<int:pk>/download/", views.download_config, name="download_config"),
    path("devices/<int:pk>/compare/", views.compare_config, name="compare_config"),
    path("devices/<int:pk>/delete-revision/", views.delete_revision, name="delete_revision"),
]
