#!/bin/bash
# Instalador/Actualizador de serv-table-ip
# Autor: XaeK
# Fecha: 2025
set -euo pipefail

APP_NAME="ServTableIP"
USER_NAME="$SUDO_USER"
BASE_URL="https://github.com/X43K"
REMOTE_DIR="${BASE_URL}/${APP_NAME}/"
INSTALL_DIR="/home/$USER_NAME/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

# Detectar usuario correctamente
if [ -n "${SUDO_USER-}" ]; then
  USER_NAME="$SUDO_USER"
else
  USER_NAME="$(logname 2>/dev/null || whoami)"
fi

echo "=============================================="
echo " Instalador de $APP_NAME"
echo "=============================================="
echo "Usuario detectado: $USER_NAME"
echo "URL remota: $REMOTE_DIR"
echo "Ruta de instalación: $INSTALL_DIR"
echo

# Comprobar herramientas necesarias
for cmd in curl wget tar unzip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    if [ "$cmd" = "curl" ] || [ "$cmd" = "wget" ]; then
      echo "ERROR: falta '$cmd'. Instálalo: sudo apt update && sudo apt install $cmd"
      exit 1
    fi
  fi
done

# Crear carpeta de instalación
sudo mkdir -p "$INSTALL_DIR"
sudo chown "${USER_NAME}":"${USER_NAME}" "$INSTALL_DIR"

echo "[1/6] Probando acceso a la URL remota..."
http_code="$(curl -s -o /dev/null -w '%{http_code}' "$REMOTE_DIR" || echo "000")"
echo " -> Código HTTP: $http_code"

downloaded=false

if [ "$http_code" = "200" ]; then
  page="$(curl -s "$REMOTE_DIR" || true)"

  if echo "$page" | grep -qi "Index of\|Parent Directory\|href"; then
    echo " [Info] Listado de directorio detectado. Descargando con wget..."
    sudo wget -q -r -np -nH --cut-dirs=2 -R "index.html*" -P "$INSTALL_DIR" "$REMOTE_DIR/" || true
    downloaded=true
  else
    echo " [Info] No hay listado público, buscando archivos empaquetados..."
    for arc in "${BASE_URL}/${APP_NAME}.tar.gz" "${BASE_URL}/${APP_NAME}.zip" "${REMOTE_DIR}${APP_NAME}.tar.gz" "${REMOTE_DIR}${APP_NAME}.zip"; do
      code="$(curl -s -o /dev/null -w '%{http_code}' "$arc" || echo "000")"
      if [ "$code" = "200" ]; then
        echo " [Info] Encontrado paquete: $arc"
        tmpfile="$(mktemp)"
        sudo wget -q -O "$tmpfile" "$arc"
        sudo chown "${USER_NAME}":"${USER_NAME}" "$tmpfile"
        mkdir -p /tmp/${APP_NAME}_extract
        if [[ "$arc" == *.tar.gz ]]; then
          tar -xzf "$tmpfile" -C /tmp/${APP_NAME}_extract || true
        else
          unzip -q "$tmpfile" -d /tmp/${APP_NAME}_extract || true
        fi
        sudo cp -a /tmp/${APP_NAME}_extract/. "$INSTALL_DIR"/
        rm -rf /tmp/${APP_NAME}_extract "$tmpfile"
        downloaded=true
        break
      fi
    done

    if [ "$downloaded" = false ]; then
      script_url="${REMOTE_DIR}start-latest-serv.sh"
      echo " [Info] Intentando descargar script directo: $script_url"
      if curl -s -I --fail "$script_url" >/dev/null 2>&1; then
        sudo wget -q -O "${INSTALL_DIR}/start-latest-serv.sh" "$script_url"
        downloaded=true
      else
        echo " [Warn] No se encontró start-latest-serv.sh directamente."
      fi
    fi
  fi
else
  echo " [Error] La URL devolvió HTTP $http_code. No se puede acceder."
fi

# Normalizar estructura si se creó subcarpeta redundante
if [ -d "${INSTALL_DIR}/${APP_NAME}" ] && [ "$(ls -A "${INSTALL_DIR}/${APP_NAME}" 2>/dev/null)" ]; then
  echo " [Info] Normalizando estructura: moviendo ${INSTALL_DIR}/${APP_NAME}/* -> ${INSTALL_DIR}/"
  sudo mv "${INSTALL_DIR}/${APP_NAME}/"* "${INSTALL_DIR}/" || true
  sudo rmdir "${INSTALL_DIR}/${APP_NAME}" || true
fi

# Verificación final de archivos descargados
if [ "$downloaded" = false ] || [ -z "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
  echo
  echo "❌ No se pudo descargar el contenido automáticamente."
  echo "Diagnóstico breve:"
  echo " - Código HTTP: $http_code"
  echo " - Primeras líneas del HTML remoto (si hay):"
  curl -s "$REMOTE_DIR" | head -n 40 || true
  exit 2
fi

# Ajustar permisos
echo "[2/6] Ajustando permisos..."
sudo find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
sudo find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
sudo find "$INSTALL_DIR" -type f -name "*.sh" -exec chmod +x {} \;

# Asegurar que el sistema tiene soporte UTF-8
echo "[3/6] Verificando locales UTF-8..."
if ! locale -a | grep -qi "es_ES.utf8"; then
  sudo locale-gen es_ES.UTF-8
  sudo update-locale LANG=es_ES.UTF-8
fi

# Instalar Scapy desde apt
echo "[4/6] Verificando e instalando scapy si falta..."
if ! python3 -c "import scapy.all" >/dev/null 2>&1; then
  echo " -> Scapy no está instalado. Instalando vía apt..."
  sudo apt update
  sudo apt install -y python3-scapy
else
  echo " -> Scapy ya está instalado."
fi

# Crear servicio systemd
echo "[5/6] Creando servicio systemd en $SERVICE_FILE ..."
sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Servicio Python Escaneo de Red
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

# Recargar systemd y lanzar servicio
echo "[6/6] Recargando systemd y lanzando servicio..."
sudo systemctl daemon-reload
sudo systemctl enable ${APP_NAME}.service || true
sudo systemctl restart ${APP_NAME}.service || {
  echo "❌ Error al iniciar el servicio. Log reciente:"
  sudo journalctl -u ${APP_NAME}.service --no-pager -n 40
  exit 1
}

echo
echo "✅ Instalación/actualización completada correctamente."
echo "Puedes revisar logs con:"
echo "   sudo journalctl -u ${APP_NAME}.service -f"
cat /home/$USER_NAME/${APP_NAME}/LEEME.md
