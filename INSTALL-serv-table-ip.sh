#!/bin/bash
# Instalador de ServTableIP
# Autor: XaeK
# Fecha: 2025
set -euo pipefail

APP_NAME="ServTableIP"
GITHUB_USER="X43K"
REPO_URL="https://github.com/${GITHUB_USER}/${APP_NAME}"
ZIP_URL="${REPO_URL}/archive/refs/heads/main.zip"
INSTALL_DIR="/home/${SUDO_USER:-$(logname 2>/dev/null || whoami)}/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

# --- Detectar usuario ---
if [ -n "${SUDO_USER-}" ]; then
  USER_NAME="$SUDO_USER"
else
  USER_NAME="$(logname 2>/dev/null || whoami)"
fi

echo "=============================================="
echo " Instalador de $APP_NAME"
echo "=============================================="
echo "Usuario detectado: $USER_NAME"
echo "Repositorio: $REPO_URL"
echo "Ruta de instalación: $INSTALL_DIR"
echo

# --- Verificar herramientas necesarias ---
for cmd in curl unzip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: falta '$cmd'. Instálalo: sudo apt update && sudo apt install $cmd"
    exit 1
  fi
done

# --- Crear carpeta de instalación ---
sudo mkdir -p "$INSTALL_DIR"
sudo chown "${USER_NAME}:${USER_NAME}" "$INSTALL_DIR"

# --- Descargar ZIP de GitHub ---
echo "[1/6] Descargando desde GitHub..."
tmpzip="$(mktemp)"
if curl -L -o "$tmpzip" "$ZIP_URL"; then
  echo " -> Archivo descargado correctamente."
else
  echo "❌ Error al descargar el ZIP del repositorio."
  exit 1
fi

# --- Extraer y copiar contenido ---
echo "[2/6] Extrayendo archivos..."
tmpdir="$(mktemp -d)"
unzip -q "$tmpzip" -d "$tmpdir"
rm "$tmpzip"

# La carpeta extraída tiene formato: ServTableIP-main/
SRC_DIR="$(find "$tmpdir" -maxdepth 1 -type d -name "${APP_NAME}-*" | head -n1)"

if [ -z "$SRC_DIR" ]; then
  echo "❌ No se encontró el contenido del repositorio tras descomprimir."
  exit 2
fi

sudo rm -rf "${INSTALL_DIR:?}/"*
sudo cp -a "$SRC_DIR"/. "$INSTALL_DIR"/
sudo chown -R "${USER_NAME}:${USER_NAME}" "$INSTALL_DIR"
rm -rf "$tmpdir"

echo " -> Archivos copiados a $INSTALL_DIR"

# --- Ajustar permisos ---
echo "[3/6] Ajustando permisos..."
sudo find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
sudo find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
sudo find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# --- Verificar locales ---
echo "[4/6] Verificando locales UTF-8..."
if ! locale -a | grep -qi "es_ES.utf8"; then
  sudo locale-gen es_ES.UTF-8
  sudo update-locale LANG=es_ES.UTF-8
fi

# --- Instalar Scapy si falta ---
echo "[5/6] Verificando e instalando Scapy..."
if ! python3 -c "import scapy.all" >/dev/null 2>&1; then
  echo " -> Scapy no está instalado. Instalando vía apt..."
  sudo apt update
  sudo apt install -y python3-scapy
else
  echo " -> Scapy ya está instalado."
fi

# --- Crear servicio systemd ---
echo "[6/6] Creando servicio systemd..."
sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Servicio Python Escaneo de Red - ${APP_NAME}
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/start-latest-serv.sh
WorkingDirectory=${INSTALL_DIR}
StandardOutput=inherit
StandardError=inherit
Restart=always
User=${USER_NAME}
Environment=LANG=en_US.UTF-8
Environment=PYTHONIOENCODING=utf-8
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# --- Habilitar y arrancar servicio ---
sudo systemctl daemon-reload
sudo systemctl enable "${APP_NAME}.service" || true
sudo systemctl restart "${APP_NAME}.service" || {
  echo "❌ Error al iniciar el servicio. Log reciente:"
  sudo journalctl -u "${APP_NAME}.service" --no-pager -n 40
  exit 1
}

echo
echo "✅ Instalación/actualización completada correctamente."
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u ${APP_NAME}.service -f"

if [ -f "${INSTALL_DIR}/LEEME.md" ]; then
  echo
  cat "${INSTALL_DIR}/LEEME.md"
fi