#!/bin/bash
# =============================================================
#  Actualizador inteligente de ServTableIP (GitHub)
#  - Elimina versiones antiguas ServTableIP-*.py
#  - Borra credservpas.xk si la versión < 9.0
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

# --- [5/6] Copiar archivos nuevos ---
echo "[5/6] Copiando archivos nuevos..."
shopt -s globstar nullglob
for f in "$SRC_DIR"/**/*; do
    [ -f "$f" ] || continue
    rel_path="${f#$SRC_DIR/}"
    dest="$INSTALL_DIR/$rel_path"

    if [[ "$rel_path" == logs/* ]]; then
        continue
    fi

    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    echo " -> Copiado: $rel_path"
done

# --- NUEVO BLOQUE: hacer ejecutables todos los *.sh ---
echo "[5.1] Ajustando permisos de ejecución en scripts..."
sudo find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;
echo "   ✅ Todos los scripts *.sh marcados como ejecutables."

# --- NUEVO BLOQUE: aplicar permisos 777 a todo ---
echo "[5.2] Aplicando permisos 777 a todo el directorio..."
sudo chmod -R 777 "$INSTALL_DIR"
echo "   ✅ Permisos 777 aplicados a todos los archivos y carpetas."

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
echo "   - Versiones antiguas eliminadas"
echo "   - credservpas.xk gestionado según versión local"
echo "   - *.sh marcados como ejecutables"
echo "   - Permisos 777 aplicados a todo el directorio"
echo "   - Commit actualizado: ${remote_commit:0:7}"
echo
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u $APP_NAME -f"
