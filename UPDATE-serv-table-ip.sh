#!/bin/bash
# Actualizador inteligente de ServTableIP (GitHub)
# Solo sobrescribe archivos que cambien, preserva credservpas.xk y logs
# Autor: XaeK
# Fecha: 2025
set -euo pipefail

APP_NAME="ServTableIP"
GITHUB_USER="X43K"
REPO_URL="https://github.com/${GITHUB_USER}/${APP_NAME}"
COMMITS_API="https://api.github.com/repos/${GITHUB_USER}/${APP_NAME}/commits/main"
ZIP_URL="${REPO_URL}/archive/refs/heads/main.zip"

USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
INSTALL_DIR="/home/${USER_NAME}/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
TMP_UPDATE_DIR="$(mktemp -d)"
COMMIT_FILE="${INSTALL_DIR}/.last_commit"

echo "=============================================="
echo " Actualizador inteligente de $APP_NAME"
echo "=============================================="
echo "Usuario detectado: $USER_NAME"
echo "Repositorio: $REPO_URL"
echo "Ruta de instalación: $INSTALL_DIR"
echo

# --- Comprobar herramientas necesarias ---
for cmd in curl unzip sha256sum systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: falta '$cmd'. Instálalo antes de continuar."
        exit 1
    fi
done

# --- [0/6] Comprobar si hay nueva versión en GitHub ---
echo "[0/6] Comprobando si hay una versión más reciente..."
remote_commit="$(curl -s "$COMMITS_API" | grep -m1 '"sha":' | cut -d '"' -f4 || echo "desconocido")"

if [ -z "$remote_commit" ] || [ "$remote_commit" = "desconocido" ]; then
    echo "⚠️  No se pudo obtener el hash del último commit remoto (sin conexión o API limitada)."
else
    if [ -f "$COMMIT_FILE" ]; then
        local_commit="$(cat "$COMMIT_FILE" 2>/dev/null || echo "")"
        if [ "$remote_commit" = "$local_commit" ]; then
            echo "✅ Ya tienes la versión más reciente (${remote_commit:0:7})."
            exit 0
        else
            echo "📦 Nueva versión detectada: ${remote_commit:0:7}"
        fi
    else
        echo "ℹ️ No hay commit local registrado, se descargará la versión actual."
    fi
fi

# --- [1/6] Detener servicio ---
if systemctl is-active --quiet "$APP_NAME"; then
    echo "[1/6] Deteniendo servicio $APP_NAME..."
    sudo systemctl stop "$APP_NAME"
fi

# --- [2/6] Descargar ZIP del repositorio ---
echo "[2/6] Descargando actualización desde GitHub..."
TMP_ZIP="$(mktemp)"
if ! curl -L -o "$TMP_ZIP" "$ZIP_URL"; then
    echo "❌ No se pudo descargar el paquete desde GitHub."
    rm -rf "$TMP_UPDATE_DIR"
    exit 2
fi

# --- [3/6] Descomprimir y sincronizar archivos ---
unzip -q "$TMP_ZIP" -d "$TMP_UPDATE_DIR"
rm "$TMP_ZIP"
SRC_DIR="$(find "$TMP_UPDATE_DIR" -maxdepth 1 -type d -name "${APP_NAME}-*" | head -n1)"

if [ -z "$SRC_DIR" ]; then
    echo "❌ No se encontró contenido tras descomprimir el repositorio."
    rm -rf "$TMP_UPDATE_DIR"
    exit 3
fi

echo "[3/6] Sincronizando archivos modificados..."
shopt -s globstar nullglob
for f in "$SRC_DIR"/**/*; do
    [ -f "$f" ] || continue
    rel_path="${f#$SRC_DIR/}"
    dest="$INSTALL_DIR/$rel_path"

    # Preservar credservpas.xk y logs
    if [[ "$rel_path" == "credservpas.xk" && -f "$dest" ]]; then
        echo " -> Preservando credservpas.xk"
        continue
    fi
    if [[ "$rel_path" == logs/* ]]; then
        continue
    fi

    mkdir -p "$(dirname "$dest")"

    # Solo sobrescribir si cambió el hash
    if [ ! -f "$dest" ] || ! cmp -s <(sha256sum "$f" | awk '{print $1}') <(sha256sum "$dest" | awk '{print $1}'); then
        cp -a "$f" "$dest"
        echo " -> Actualizado: $rel_path"
    fi
done

# --- [4/6] Ajustar permisos ---
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# --- [5/6] Guardar commit actualizado ---
if [ -n "$remote_commit" ] && [ "$remote_commit" != "desconocido" ]; then
    echo "$remote_commit" > "$COMMIT_FILE"
    echo "📝 Commit registrado localmente: ${remote_commit:0:7}"
fi

# --- [6/6] Reiniciar servicio ---
echo "[6/6] Reiniciando servicio $APP_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$APP_NAME"

echo
echo "✅ Actualización inteligente completada."
echo "   - credservpas.xk preservado"
echo "   - logs y archivos locales conservados"
echo "   - commit actualizado: ${remote_commit:0:7}"
echo
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u $APP_NAME -f"

if [ -f "${INSTALL_DIR}/LEEME2.md" ]; then
    echo
    cat "${INSTALL_DIR}/LEEME2.md"
fi