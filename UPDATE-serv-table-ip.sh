#!/bin/bash
# =============================================================
#  Actualizador inteligente de ServTableIP (GitHub)
#  - Elimina versiones antiguas ServTableIP-*.py
#  - Borra credservpas.xk si la versión < 9.0
#  - Solo sobrescribe archivos modificados (hash distinto)
#  - Hace ejecutables todos los *.sh nuevos (con sudo)
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
echo "Ruta de instalación: $INSTALL_DIR"
echo


# --- [0.0] Comprobar y actualizar oui.txt desde IEEE ---
echo "[0.0] Comprobando si el listado OUI oficial ha cambiado..."
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
            echo "$remote_date" > "$OUI_META"
            echo "✅ Archivo oui.txt actualizado correctamente."
        else
            echo "⚠️  Error al descargar la nueva versión del oui.txt."
        fi
    else
        echo "✅ El archivo oui.txt ya está actualizado."
    fi
else
    echo "⚠️  No se pudo comprobar la fecha remota de oui.txt."
fi


# --- [0/6] Comprobaciones previas ---
for cmd in curl unzip sha256sum systemctl bc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "❌ ERROR: falta '$cmd'. Instálalo antes de continuar."
        exit 1
    fi
done

# --- [1/6] Comprobar si hay nueva versión ---
echo "[1/6] Comprobando si hay una versión más reciente..."
remote_commit="$(curl -s "$COMMITS_API" | grep -m1 '"sha":' | cut -d '"' -f4 || echo "desconocido")"

if [ -z "$remote_commit" ] || [ "$remote_commit" = "desconocido" ]; then
    echo "⚠️  No se pudo obtener el hash del último commit remoto."
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

# --- [2/6] Detener servicio ---
if systemctl is-active --quiet "$APP_NAME"; then
    echo "[2/6] Deteniendo servicio $APP_NAME..."
    sudo systemctl stop "$APP_NAME"
fi

# --- [3/6] Descargar ZIP del repositorio ---
echo "[3/6] Descargando actualización desde GitHub..."
TMP_ZIP="$(mktemp)"
if ! curl -L -o "$TMP_ZIP" "$ZIP_URL"; then
    echo "❌ No se pudo descargar el paquete desde GitHub."
    rm -rf "$TMP_UPDATE_DIR"
    exit 2
fi

unzip -q "$TMP_ZIP" -d "$TMP_UPDATE_DIR"
rm "$TMP_ZIP"
SRC_DIR="$(find "$TMP_UPDATE_DIR" -maxdepth 1 -type d -name "${APP_NAME}-*" | head -n1)"

if [ -z "$SRC_DIR" ]; then
    echo "❌ No se encontró contenido tras descomprimir el repositorio."
    rm -rf "$TMP_UPDATE_DIR"
    exit 3
fi

# --- [4/6] Detectar versión local y limpiar ---
echo "[4/6] Analizando instalación actual..."
current_version="$(find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' | sed -E 's/.*ServTableIP-([0-9.]+)\.py/\1/' | sort -V | tail -n1)"
echo "   Versión local actual: ${current_version:-desconocida}"

echo "   -> Eliminando versiones antiguas ServTableIP-*.py..."
find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' -exec rm -f {} \;

if [[ -n "$current_version" && $(echo "$current_version < 9.0" | bc -l) -eq 1 ]]; then
    if [ -f "$INSTALL_DIR/credservpas.xk" ]; then
        echo "⚠️  Versión anterior a 9.0 detectada — eliminando credservpas.xk..."
        rm -f "$INSTALL_DIR/credservpas.xk"
    fi
else
    echo "   credservpas.xk preservado (versión >= 9.0)"
fi

# --- [5/6] Copiar solo archivos modificados ---
echo "[5/6] Sincronizando archivos modificados..."
shopt -s globstar nullglob
for f in "$SRC_DIR"/**/*; do
    [ -f "$f" ] || continue
    rel_path="${f#$SRC_DIR/}"
    dest="$INSTALL_DIR/$rel_path"

    # No tocar logs ni credenciales si ya existen
    if [[ "$rel_path" == "logs/"* ]]; then
        continue
    fi
    if [[ "$rel_path" == "credservpas.xk" && -f "$dest" ]]; then
        echo " -> Preservando credservpas.xk"
        continue
    fi

    mkdir -p "$(dirname "$dest")"

    # Solo sobrescribir si cambia el hash
    if [ ! -f "$dest" ] || ! cmp -s <(sha256sum "$f" | awk '{print $1}') <(sha256sum "$dest" | awk '{print $1}'); then
        cp -a "$f" "$dest"
        echo " -> Actualizado: $rel_path"
    fi
done

# --- [5.1] Hacer ejecutables todos los scripts .sh ---
echo "[5.1] Ajustando permisos de ejecución..."
sudo find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# --- [5.2] Permisos 777 a todo ---
echo "[5.2] Aplicando permisos 777 a todo el directorio..."
sudo chmod -R 777 "$INSTALL_DIR"

# --- [6/6] Registrar commit y reiniciar servicio ---
if [ -n "$remote_commit" ] && [ "$remote_commit" != "desconocido" ]; then
    echo "$remote_commit" > "$COMMIT_FILE"
    echo "📝 Commit registrado localmente: ${remote_commit:0:7}"
fi

echo "[6/6] Reiniciando servicio $APP_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$APP_NAME"

echo
echo "✅ Actualización completada correctamente."
echo "   - Solo archivos modificados fueron actualizados"
echo "   - Versiones antiguas eliminadas"
echo "   - credservpas.xk gestionado según versión"
echo "   - *.sh ejecutables + permisos 777 aplicados"
echo
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u $APP_NAME -f"

if [ -f "${INSTALL_DIR}/static/LEEME2.md" ]; then
  echo
  cat "${INSTALL_DIR}/static/LEEME2.md"
fi