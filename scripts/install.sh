#!/bin/bash
set -euo pipefail

STORAGE_ROOT="/opt/libreoxi"
NETBOX_USER="netbox"
NETBOX_GROUP="netbox"
PLUGIN_REPO="git+https://github.com/ArK761/NetboxLibre_OxI.git"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this installer as root."
    echo "Example: sudo ./scripts/install.sh"
    exit 1
fi

if ! id "$NETBOX_USER" >/dev/null 2>&1; then
    echo "ERROR: system user '$NETBOX_USER' does not exist."
    exit 1
fi

if ! getent group "$NETBOX_GROUP" >/dev/null 2>&1; then
    echo "ERROR: system group '$NETBOX_GROUP' does not exist."
    exit 1
fi

echo "Creating LibreOXI storage directory: $STORAGE_ROOT"
install -d -o "$NETBOX_USER" -g "$NETBOX_GROUP" -m 0750 "$STORAGE_ROOT"

if [ ! -x /opt/netbox/venv/bin/pip ]; then
    echo "ERROR: NetBox virtual environment not found at /opt/netbox/venv"
    exit 1
fi

echo "Installing/upgrading NetBox LibreOXI from GitHub..."
/opt/netbox/venv/bin/pip install --upgrade --force-reinstall "$PLUGIN_REPO"

echo "Running LibreOXI database migrations..."
cd /opt/netbox/netbox
/opt/netbox/venv/bin/python manage.py migrate netbox_libreoxi --no-input

chown -R "$NETBOX_USER:$NETBOX_GROUP" "$STORAGE_ROOT"
chmod 0750 "$STORAGE_ROOT"

echo
echo "NetBox LibreOXI installation finished."
echo "Storage: $STORAGE_ROOT"
echo "Owner:   $NETBOX_USER:$NETBOX_GROUP"
echo "Mode:    750"
