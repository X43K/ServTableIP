#!/bin/bash
# Actualizador inteligente de serv-table-ip
# Solo sobrescribe archivos que cambien, preserva credservpas.xk y logs
# Autor: XaeK
# Fecha: 2025
set -euo pipefail

APP_NAME="ServTableIP"
USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
BASE_URL="https://github.com/X43K"
REMOTE_DIR="${BASE_URL}/${APP_NAME}/"
INSTALL_DIR="/home/$USER_NAME/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
TMP_UPDATE_DIR="$(mktemp -d)"

echo "=============================================="
echo " Actualizador inteligente de $APP_NAME"
echo "=============================================="
echo "Usuario detectado: $USER_NAME"
echo "Ruta de instalación: $INSTALL_DIR"
echo

# Comprobar herramientas necesarias
for cmd in curl wget tar unzip rsync sha256sum systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: falta '$cmd'. Instálalo antes de continuar."
        exit 1
    fi
done

# Detener servicio si existe
if systemctl is-active --quiet "$APP_NAME"; then
    echo "[1/5] Deteniendo servicio $APP_NAME..."
    sudo systemctl stop "$APP_NAME"
fi

# Descargar archivos más recientes a carpeta temporal
echo "[2/5] Descargando archivos al directorio temporal $TMP_UPDATE_DIR..."
downloaded=false
http_code="$(curl -s -o /dev/null -w '%{http_code}' "$REMOTE_DIR" || echo "000")"
if [ "$http_code" = "200" ]; then
    page="$(curl -s "$REMOTE_DIR" || true)"
    if echo "$page" | grep -qi "Index of\|Parent Directory\|href"; then
        wget -q -r -np -nH --cut-dirs=2 -R "index.html*" -P "$TMP_UPDATE_DIR" "$REMOTE_DIR/" || true
        downloaded=true
    else
        for ext in tar.gz zip; do
            pkg_url="${REMOTE_DIR}${APP_NAME}.${ext}"
            code="$(curl -s -o /dev/null -w '%{http_code}' "$pkg_url" || echo "000")"
            if [ "$code" = "200" ]; then
                tmpfile="$(mktemp)"
                wget -q -O "$tmpfile" "$pkg_url"
                mkdir -p "$TMP_UPDATE_DIR/extract"
                if [[ "$ext" == "tar.gz" ]]; then
                    tar -xzf "$tmpfile" -C "$TMP_UPDATE_DIR/extract"
                else
                    unzip -q "$tmpfile" -d "$TMP_UPDATE_DIR/extract"
                fi
                mv "$TMP_UPDATE_DIR/extract"/* "$TMP_UPDATE_DIR"/
                rm -rf "$TMP_UPDATE_DIR/extract" "$tmpfile"
                downloaded=true
                break
            fi
        done
    fi
fi

if [ "$downloaded" = false ]; then
    echo "❌ No se pudieron descargar los archivos."
    rm -rf "$TMP_UPDATE_DIR"
    exit 2
fi

# Comparar archivos y sobrescribir solo si cambian
echo "[3/5] Sincronizando archivos modificados..."
shopt -s globstar nullglob
for f in "$TMP_UPDATE_DIR"/**/*; do
    [ -f "$f" ] || continue
    rel_path="${f#$TMP_UPDATE_DIR/}"
    dest="$INSTALL_DIR/$rel_path"

    # Preservar credservpas.xk
    if [[ "$rel_path" == "credservpas.xk" && -f "$dest" ]]; then
        echo " -> Preservando credservpas.xk"
        continue
    fi

    # Crear directorio destino si no existe
    mkdir -p "$(dirname "$dest")"

    # Solo sobrescribir si no existe o cambió el hash
    if [ ! -f "$dest" ] || ! cmp -s <(sha256sum "$f") <(sha256sum "$dest"); then
        cp -a "$f" "$dest"
        echo " -> Actualizado: $rel_path"
    fi
done

# Ajustar permisos de forma segura
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# Limpiar temporal
rm -rf "$TMP_UPDATE_DIR"

# Reiniciar el servicio
echo "[4/5] Reiniciando servicio $APP_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$APP_NAME"

echo
echo "✅ Actualización inteligente completada. credservpas.xk preservado, logs y archivos locales conservados."
echo "Puedes revisar logs con: sudo journalctl -u $APP_NAME -f"
cat /home/$USER_NAME/${APP_NAME}/LEEME2.md
