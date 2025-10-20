#!/bin/bash
# Actualizador inteligente de ServTableIP (GitHub)
# Versión mejorada: limpia versiones antiguas y gestiona credservpas.xk según versión.
# Autor: XaeK (modificado por GPT-5)
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

# --- [0/6] Comprobar si hay una versión más reciente ---
echo "[0/6] Comprobando si hay una versión más reciente..."
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

# --- [3/6] Descomprimir y preparar ---
unzip -q "$TMP_ZIP" -d "$TMP_UPDATE_DIR"
rm "$TMP_ZIP"
SRC_DIR="$(find "$TMP_UPDATE_DIR" -maxdepth 1 -type d -name "${APP_NAME}-*" | head -n1)"

if [ -z "$SRC_DIR" ]; then
    echo "❌ No se encontró contenido tras descomprimir el repositorio."
    rm -rf "$TMP_UPDATE_DIR"
    exit 3
fi

# --- NUEVO BLOQUE: Detectar versión local actual ---
echo "[3.1] Detectando versión local actual..."
current_version="$(find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' | sed -E 's/.*ServTableIP-([0-9.]+)\.py/\1/' | sort -V | tail -n1)"
echo "   Versión local actual: ${current_version:-desconocida}"

# --- NUEVO BLOQUE: Limpiar versiones antiguas ---
echo "[3.2] Eliminando versiones antiguas..."
find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' -exec rm -f {} \;
echo "   ✅ Versiones antiguas eliminadas."

# --- NUEVO BLOQUE: Eliminar credservpas.xk si versión < 9.0 ---
if [[ -n "$current_version" && $(echo "$current_version < 9.0" | bc -l) -eq 1 ]]; then
    if [ -f "$INSTALL_DIR/credservpas.xk" ]; then
        echo "⚠️  Versión anterior a 9.0 detectada — eliminando credservpas.xk..."
        rm -f "$INSTALL_DIR/credservpas.xk"
    fi
else
    echo "   credservpas.xk preservado (versión >= 9.0)"
fi

# --- [4/6] Copiar archivos nuevos ---
echo "[4/6] Copiando archivos nuevos..."
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

# --- [5/6] Permisos y commit ---
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

if [ -n "$remote_commit" ] && [ "$remote_commit" != "desconocido" ]; then
    echo "$remote_commit" > "$COMMIT_FILE"
    echo "📝 Commit registrado localmente: ${remote_commit:0:7}"
fi

# --- [6/6] Reiniciar servicio ---
echo "[6/6] Reiniciando servicio $APP_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$APP_NAME"

echo
echo "✅ Actualización completada correctamente."
echo "   - Versiones antiguas eliminadas"
echo "   - credservpas.xk tratado según versión local"
echo "   - Commit actualizado: ${remote_commit:0:7}"
echo
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u $APP_NAME -f"
#!/bin/bash
# Actualizador inteligente de ServTableIP (GitHub)
# Versión mejorada: limpia versiones antiguas y gestiona credservpas.xk según versión.
# Autor: XaeK (modificado por GPT-5)
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

# --- [0/6] Comprobar si hay una versión más reciente ---
echo "[0/6] Comprobando si hay una versión más reciente..."
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

# --- [3/6] Descomprimir y preparar ---
unzip -q "$TMP_ZIP" -d "$TMP_UPDATE_DIR"
rm "$TMP_ZIP"
SRC_DIR="$(find "$TMP_UPDATE_DIR" -maxdepth 1 -type d -name "${APP_NAME}-*" | head -n1)"

if [ -z "$SRC_DIR" ]; then
    echo "❌ No se encontró contenido tras descomprimir el repositorio."
    rm -rf "$TMP_UPDATE_DIR"
    exit 3
fi

# --- NUEVO BLOQUE: Detectar versión local actual ---
echo "[3.1] Detectando versión local actual..."
current_version="$(find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' | sed -E 's/.*ServTableIP-([0-9.]+)\.py/\1/' | sort -V | tail -n1)"
echo "   Versión local actual: ${current_version:-desconocida}"

# --- NUEVO BLOQUE: Limpiar versiones antiguas ---
echo "[3.2] Eliminando versiones antiguas..."
find "$INSTALL_DIR" -maxdepth 1 -type f -name 'ServTableIP-*.py' -exec rm -f {} \;
echo "   ✅ Versiones antiguas eliminadas."

# --- NUEVO BLOQUE: Eliminar credservpas.xk si versión < 9.0 ---
if [[ -n "$current_version" && $(echo "$current_version < 9.0" | bc -l) -eq 1 ]]; then
    if [ -f "$INSTALL_DIR/credservpas.xk" ]; then
        echo "⚠️  Versión anterior a 9.0 detectada — eliminando credservpas.xk..."
        rm -f "$INSTALL_DIR/credservpas.xk"
    fi
else
    echo "   credservpas.xk preservado (versión >= 9.0)"
fi

# --- [4/6] Copiar archivos nuevos ---
echo "[4/6] Copiando archivos nuevos..."
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

# --- [5/6] Permisos y commit ---
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

if [ -n "$remote_commit" ] && [ "$remote_commit" != "desconocido" ]; then
    echo "$remote_commit" > "$COMMIT_FILE"
    echo "📝 Commit registrado localmente: ${remote_commit:0:7}"
fi

# --- [6/6] Reiniciar servicio ---
echo "[6/6] Reiniciando servicio $APP_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$APP_NAME"

echo
echo "✅ Actualización completada correctamente."
echo "   - Versiones antiguas eliminadas"
echo "   - credservpas.xk tratado según versión local"
echo "   - Commit actualizado: ${remote_commit:0:7}"
echo
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u $APP_NAME -f"
