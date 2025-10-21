#!/bin/bash
# =============================================================
#  Actualizador inteligente de ServTableIP (GitHub)
#  - Elimina versiones antiguas ServTableIP-*.py
#  - Borra credservpas.xk si la versión < 9.0
#  - Solo sobrescribe archivos modificados (hash distinto)
#  - Hace ejecutables todos los *.sh nuevos (con sudo)
#  - Actualiza base de datos oficial oui
#  - Aplica permisos 777 a todo el directorio ServTableIP
# =============================================================
#  Autor: XaeK
#  Fecha: 2025
# =============================================================

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

# --- [0] Comprobar y actualizar oui.txt desde IEEE ---
echo "[0] Comprobando si el listado OUI oficial ha cambiado..."
OUI_URL="https://standards-oui.ieee.org/oui/oui.txt"
OUI_FILE="${INSTALL_DIR}/oui.txt"
OUI_META="${INSTALL_DIR}/oui_last_modified.txt"

remote_date="$(curl -sI "$OUI_URL" | grep -i '^Last-Modified:' | sed 's/Last-Modified: //I' | tr -d '\r')"
local_date="$(cat "$OUI_META" 2>/dev/null || echo "")"

if [ -n "$remote_date" ]; then
    if [ "$remote_date" != "$local_date" ]; then
        echo "📡 Nueva versión detectada del listado OUI. Descargando..."
        if curl -s -o "${OUI_FILE}.tmp" "$OUI_URL"; then
            mv "${OUI_FILE}.tmp" "$OUI_FILE"
            chmod 777 "$OUI_FILE"
            echo "$remote_date" > "$OUI_META"
            echo "✅ Archivo oui.txt actualizado correctamente y permisos aplicados."
        else
            echo "⚠️  Error al descargar la nueva versión del oui.txt."
        fi
    else
        echo "✅ El archivo oui.txt ya está actualizado."
    fi
else
    echo "⚠️  No se pudo comprobar la fecha remota de oui.txt."
fi

# --- [1] Comprobar última versión del repositorio ---
echo "[1] Comprobando última versión del repositorio..."

# Obtención robusta del SHA del último commit
remote_commit="$(curl -s "$COMMITS_API" | awk -F'"' '/"sha":/ {print $4; exit}')"
local_commit="$(cat "$COMMIT_FILE" 2>/dev/null || echo "")"

if [ -z "$remote_commit" ]; then
    echo "⚠️  No se pudo obtener la última versión del repositorio desde GitHub."
elif [ "$remote_commit" != "$local_commit" ]; then
    echo "🚀 Nueva versión detectada. Descargando actualización..."
    
    # Descargar y descomprimir
    curl -sL "$ZIP_URL" -o "$TMP_UPDATE_DIR/update.zip"
    unzip -qo "$TMP_UPDATE_DIR/update.zip" -d "$TMP_UPDATE_DIR"
    UPDATE_SRC_DIR="$TMP_UPDATE_DIR/${APP_NAME}-main"

    # --- [2] Eliminar versiones antiguas de ServTableIP-*.py ---
    echo "[2] Eliminando versiones antiguas..."
    find "$INSTALL_DIR" -maxdepth 1 -name 'ServTableIP-*.py' -type f -exec rm -f {} \;

    # --- [3] Copiar archivos nuevos solo si cambian (hash distinto) ---
    echo "[3] Aplicando actualización de archivos..."
    rsync -rc --ignore-existing "$UPDATE_SRC_DIR/" "$INSTALL_DIR/"

    # --- [4] Hacer ejecutables los scripts .sh ---
    echo "[4] Aplicando permisos de ejecución a scripts nuevos..."
    find "$INSTALL_DIR" -maxdepth 1 -name '*.sh' -type f -exec chmod +x {} \;

    # --- [5] Aplicar permisos 777 a todo el directorio ---
    echo "[5] Aplicando permisos 777 a todo el directorio..."
    chmod -R 777 "$INSTALL_DIR"

    # Guardar commit actualizado
    echo "$remote_commit" > "$COMMIT_FILE"
    echo "✅ Actualización completada."
else
    echo "✅ Ya tienes la última versión de la aplicación instalada."
fi

# --- [6] Limpieza ---
rm -rf "$TMP_UPDATE_DIR"
echo "=============================================="
echo " Actualización finalizada."
echo "=============================================="