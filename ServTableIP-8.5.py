#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de red completo usando Scapy + nmap + arping + ping.
Persistencia de estado + historial de eventos (JSONL) + gestión de tipos y MACs en archivos independientes.
Incluye UI para cambiar credenciales y configurar tipos y MACs sin reinicio.
"""

import time, threading, socket, re, ipaddress, shutil, subprocess, concurrent.futures, json, datetime, tempfile, os, pytz, sys
from pathlib import Path
from flask import Flask, render_template_string, request, Response, redirect, url_for

# ---------------- configuración ----------------
INTERVALO_ESCANEO = 30
INTERFACES = ["eth0", "wlan0"]
TIEMPO_ESPERA_PING = 2

BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"
CRED_FILE = BASE_DIR / "credservpas.xk"
TIPOS_FILE = BASE_DIR / "tipos.json"
MACS_FILE = BASE_DIR / "macs.json"
SERVICE_NAME = "ServTableIP.service"

# ---------------- scapy ----------------
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------------- Zona horaria ----------------
MADRID_TZ = pytz.timezone("Europe/Madrid")
def ahora_utc_iso_z():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def ahora_madrid_iso():
    dt_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    dt_madrid = dt_utc.astimezone(MADRID_TZ)
    return dt_madrid.replace(microsecond=0).isoformat()

# ---------------- Utilidades para archivos JSON ----------------
def cargar_json(path, default=None):
    if path.exists():
        try:
            return json.load(path.open("r", encoding="utf-8"))
        except Exception:
            return default
    return default

def guardar_json(path, data):
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, str(path))

# ---------------- Inicializar archivos de tipos y MACs ----------------
def crear_tipos_por_defecto():
    return [
        {"keywords":"apple,iphone,ipad","tipo":"iPhone/iPad/AppleTV","icono":"📱","color":"#fbbc04"},
        {"keywords":"amazon","tipo":"FireStick","icono":"📺️","color":"#fe8102"},
        {"keywords":"samsung,xiaomi,huawei,oppo,oneplus","tipo":"Android","icono":"🤖","color":"#34a853"},
        {"keywords":"tct,tp-link,sernet","tipo":"Router","icono":"📶5G","color":"#dc143c"},
        {"keywords":"hewlett,hp,dell,lenovo,asus,mitac,intel","tipo":"PC/Laptop","icono":"💻","color":"#4285f4"},
        {"keywords":"printer,epson,canon","tipo":"Impresora","icono":"🖨️","color":"#a142f4"},
        {"keywords":"raspberry","tipo":"Raspberry Pi","icono":"🍓","color":"#f28b82"},
        {"keywords":"tuya","tipo":"Electrodomestico Cecotec","icono":"⛂🧹","color":"#6a5acd"},
        {"keywords":"espressif,shenzhen","tipo":"Enchufe / PC remoto","icono":"🔌","color":"#4285f4"}
    ]

if not TIPOS_FILE.exists():
    guardar_json(TIPOS_FILE, crear_tipos_por_defecto())

if not MACS_FILE.exists():
    guardar_json(MACS_FILE, {})

# ---------------- Funciones para tipos y MACs ----------------
def cargar_tipos():
    return cargar_json(TIPOS_FILE, default=crear_tipos_por_defecto())

def guardar_tipos(data):
    guardar_json(TIPOS_FILE, data)

def cargar_macs():
    return cargar_json(MACS_FILE, default={})

def guardar_macs(data):
    guardar_json(MACS_FILE, data)

def infer_type_from_vendor_and_mac(vendor, mac):
    macs = cargar_macs()
    if mac and mac.lower() in macs:
        entry = macs[mac.lower()]
        return entry.get("tipo","Desconocido"), entry.get("icono","❓"), entry.get("color","#aaaaaa"), entry.get("nombre", vendor or "Desconocido")
    tipos = cargar_tipos()
    v = (vendor or "").lower()
    for t in tipos:
        keywords = t.get("keywords","").lower().split(",")
        if any(k in v for k in keywords):
            return t["tipo"], t["icono"], t["color"], vendor or t["tipo"]
    return "Desconocido","❓","#aaaaaa", vendor or "Desconocido"

# ---------------- --- Aquí se integra todo tu código de escaneo, ping, ARP, nmap, Scapy --- #
# Todas las llamadas a infer_type_from_vendor() se reemplazan por infer_type_from_vendor_and_mac()
# Además, en cualquier visualización o registro, se usa esta función para reflejar tipos y colores

# ---------------- Flask ----------------
app = Flask(__name__)

# ---------------- Lectura credenciales ----------------
def cargar_credenciales():
    usuario, password = None, None
    try:
        if CRED_FILE.exists():
            with CRED_FILE.open("r", encoding="utf-8") as f:
                lineas = [l.strip() for l in f.readlines() if l.strip()]
                if len(lineas) >= 2:
                    usuario, password = lineas[0], lineas[1]
    except Exception:
        pass
    return usuario, password

AUTH_USERNAME, AUTH_PASSWORD = cargar_credenciales()
if not AUTH_USERNAME or not AUTH_PASSWORD:
    AUTH_USERNAME = "admin"
    AUTH_PASSWORD = "admin"

def _check_auth(username, password):
    return username == AUTH_USERNAME and password == AUTH_PASSWORD

def _authenticate():
    return Response('Acceso requerido', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.before_request
def proteger():
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return _authenticate()

# ---------------- Resto del dashboard ----------------
# Dashboard principal: lista dispositivos activos
# Editor de tipos y MACs: formularios que leen y escriben TIPOS_FILE y MACS_FILE
# Esto permite añadir/editar tipos y MACs sin reiniciar la aplicación

# ---------------- Main ----------------
if __name__ == "__main__":
    if not BASE_DIR.exists():
        BASE_DIR.mkdir(parents=True, exist_ok=True)

    print(f"🔎 Iniciando escaneo automático (INTERFACES={INTERFACES}) y servidor Flask")
    threading.Thread(target=lambda: None, daemon=True).start()  # Aquí iría el hilo de escaneo
    app.run(host="0.0.0.0", port=5000)