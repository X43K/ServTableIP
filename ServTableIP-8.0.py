#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de red completo usando Scapy (ARP masivo) + nmap + arping + ping.
Persistencia de estado + historial de eventos (JSONL).
Incluye UI para cambiar credenciales y reiniciar el servicio.
Incluye UI para editar reglas de detección (tipos.json).
Ejecutar como root: sudo python3 scanner_scapy_persist.py
Soporta múltiples interfaces (ej: eth0 y/o wlan0).
"""

import time
import threading
import re
import ipaddress
from pathlib import Path
import shutil
import subprocess
import concurrent.futures
from flask import Flask, render_template_string, request, Response, jsonify, url_for
import json
import datetime
import tempfile
import os
import pytz
import sys

# scapy
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------------- configuración ----------------
INTERVALO_ESCANEO = 30
INTERFACES = ["eth0", "wlan0"]
TIEMPO_ESPERA_PING = 2

# Rutas (ajusta si hace falta)
BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"    # persiste dispositivos conocidos (online + offline)
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"         # JSONL append-only (cada línea un evento)
OUI_FILE = BASE_DIR / "oui.txt"                        # fichero OUI local
CRED_FILE = BASE_DIR / "credservpas.xk"
TIPOS_FILE = BASE_DIR / "tipos.json"                   # reglas de detección editables por UI

# Servicio systemd a reiniciar cuando cambian credenciales
SERVICE_NAME = "ServTableIP.service"

# ---------------- Mostrar nombre de la aplicación / versión ----------------
try:
    _APP_FILENAME = Path(__file__).name
except Exception:
    _APP_FILENAME = Path(sys.argv[0]).name if len(sys.argv) > 0 else "unknown"

def _format_app_display(filename: str) -> str:
    stem = Path(filename).stem
    m = re.match(r'^(.+?)[\-\_\s]+v?(\d+(?:[._]\d+)*)$', stem, flags=re.I)
    if m:
        base = m.group(1)
        ver = m.group(2).replace('_', '.')
        return f"{base} v.{ver}"
    return stem

APP_DISPLAY_NAME = _format_app_display(_APP_FILENAME)

# globales
dispositivos = []
nuevos_detectados = []
desconectados = []
ultima_ips = set()
ultima_actualizacion = "Aún no se ha realizado un escaneo"
_oui_dict = None

estado_lock = threading.Lock()
tipos_lock = threading.Lock()

# ---------------- Zona horaria / utilidades de tiempo ----------------
MADRID_TZ = pytz.timezone("Europe/Madrid")

def convertir_a_horario_españa(timestamp_iso):
    if not timestamp_iso:
        return ""
    try:
        ts = timestamp_iso
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        dt_madrid = dt.astimezone(MADRID_TZ)
        return dt_madrid.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return timestamp_iso

def ahora_utc_iso_z():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def ahora_madrid_iso():
    dt_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    dt_madrid = dt_utc.astimezone(MADRID_TZ)
    return dt_madrid.replace(microsecond=0).isoformat()

# ---------------- OUI helpers ----------------
def load_oui(target_path=OUI_FILE):
    global _oui_dict
    if _oui_dict is not None:
        return _oui_dict
    d = {}
    if target_path.exists():
        try:
            data = target_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in data:
                if "(hex)" in line:
                    parts = line.split()
                    prefix = parts[0].replace("-", ":").lower()
                    vendor = " ".join(parts[2:]).strip()
                    d[prefix] = vendor
        except Exception:
            pass
    _oui_dict = d
    return _oui_dict

def normalize_mac(mac):
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if m in ("<incomplete>", "desconocida", "unknown"):
        return None
    octs = m.split(":")
    if len(octs) < 3:
        return None
    return ":".join(octs[:3])

def canonical_mac(mac):
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":").replace(".", ":")
    m_n = re.sub(r'[^0-9a-f:]', '', m)
    if ":" not in m_n and len(m_n) == 12:
        m_n = ":".join([m_n[i:i+2] for i in range(0, 12, 2)])
    parts = m_n.split(":")
    if len(parts) == 6 and all(re.fullmatch(r'[0-9a-f]{2}', p) for p in parts):
        return ":".join(parts)
    return m_n

def get_vendor(mac):
    key = normalize_mac(mac)
    if not key:
        return "Desconocido"
    oui = load_oui()
    return oui.get(key) or oui.get(key.replace(":", "")) or "Desconocido"

# ---------------- Tabla de tipos (editable por UI) ----------------
def crear_tipos_por_defecto():
    return [
        {"keywords": ["apple", "iphone", "ipad", "mac"], "tipo":"iPhone/iPad/AppleTV", "icono":"📱", "color":"#fbbc04"},
        {"keywords": ["hewlett", "hp", "dell", "lenovo", "asus", "mitac", "intel"], "tipo":"PC/Laptop", "icono":"💻", "color":"#4285f4"},
        {"keywords": ["raspberry", "b8:27:eb", "dc:a6:32"], "tipo":"Raspberry Pi", "icono":"🍓", "color":"#f28b82"},
        {"keywords": ["tplink", "tp-link", "netgear", "tenda", "huawei", "zte"], "tipo":"Router", "icono":"📶", "color":"#dc143c"},
        {"keywords": ["epson", "canon", "brother", "printer"], "tipo":"Impresora", "icono":"🖨️", "color":"#a142f4"},
        {"keywords": ["espressif", "esp8266", "esp32", "sonoff"], "tipo":"IoT/SmartDevice", "icono":"🔌", "color":"#6a5acd"},
    ]

def cargar_tipos(ruta=TIPOS_FILE):
    try:
        if ruta.exists():
            with ruta.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception:
        pass
    # si no existe o hay fallo, devolver por defecto y guardar
    default = crear_tipos_por_defecto()
    try:
        with ruta.open("w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    return default

def guardar_tipos(data, ruta=TIPOS_FILE):
    try:
        with tipos_lock:
            with ruta.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

TIPOS = cargar_tipos()

def infer_type_from_vendor(vendor, mac=None):
    """
    Determina el tipo de dispositivo, icono y color según el vendor (OUI o fabricante).
    Usa TIPOS (editable vía UI).
    """
    v = (vendor or "").lower()
    mac_l = (mac or "").lower()

    with tipos_lock:
        for regla in TIPOS:
            palabras = regla.get("keywords", []) or []
            for palabra in palabras:
                p = palabra.strip().lower()
                if not p:
                    continue
                # buscar coincidencia en vendor o en mac (útil para OUIs como b8:27:eb)
                if p in v or p in mac_l:
                    return regla.get("tipo", "Desconocido"), regla.get("icono", "❓"), regla.get("color", "#999999"), vendor
    # heurísticas simples
    if v:
        if "android" in v:
            return "Móvil Android", "📱", "#34a853", vendor
        if "microsoft" in v:
            return "PC/Laptop", "💻", "#4285f4", vendor
        if "virtual" in v or "vmware" in v:
            return "Máquina Virtual", "🖥️", "#9c27b0", vendor

    # Por defecto
    # Si la MAC parece Raspberry Pi por prefijo, usar Raspberry
    if mac_l and (mac_l.startswith("b8:27:eb") or mac_l.startswith("dc:a6:32")):
        return "Raspberry Pi", "🍓", "#f28b82", vendor

    return "Desconocido", "❓", "#aaaaaa", vendor

# ---------------- utilidades de red ----------------
def obtener_ip_de_interfaz(iface):
    try:
        salida_ip = subprocess.check_output(f"ip addr show {iface}", shell=True).decode(errors="ignore")
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida_ip)
        return match.group(1) if match else None
    except Exception:
        return None

def obtener_mascara_de_interfaz(iface):
    try:
        salida_ip = subprocess.check_output(f"ip addr show {iface}", shell=True).decode(errors="ignore")
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida_ip)
        return int(match.group(2)) if match else None
    except Exception:
        return None

def obtener_mac_interfaz(iface):
    try:
        path = Path(f"/sys/class/net/{iface}/address")
        if path.exists():
            mac = path.read_text().strip().lower()
            if mac:
                return mac
        salida = subprocess.check_output(f"ip link show {iface}", shell=True).decode(errors="ignore")
        m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", salida)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return None

def interfaz_existe(iface):
    return Path(f"/sys/class/net/{iface}").exists()

def leer_tabla_arp():
    d = {}
    try:
        salida = subprocess.check_output("ip neigh", shell=True).decode(errors="ignore")
        for l in salida.splitlines():
            partes = l.split()
            if len(partes) >= 5:
                ip = partes[0]
                if "lladdr" in partes:
                    idx = partes.index("lladdr")
                    mac = partes[idx+1]
                    d[ip] = mac
    except Exception:
        pass
    if not d:
        try:
            salida = subprocess.check_output("arp -n", shell=True).decode(errors="ignore")
            for linea in salida.splitlines()[1:]:
                partes = re.split(r'\s+', linea)
                if len(partes) >= 3:
                    ip = partes[0]
                    mac = partes[2]
                    d[ip] = mac
        except Exception:
            pass
    return d

# ---------------- descubrimiento con nmap (opcional) ----------------
def escanear_con_nmap(red):
    nmap_bin = shutil.which("nmap")
    resultados = []
    if not nmap_bin:
        return resultados
    try:
        salida = subprocess.check_output([nmap_bin, "-sn", str(red)], stderr=subprocess.DEVNULL).decode(errors="ignore")
        current_ip = None
        for line in salida.splitlines():
            line = line.strip()
            m = re.match(r"Nmap scan report for (\S+)", line)
            if m:
                current_ip = m.group(1)
                continue
            if current_ip:
                mm = re.match(r"MAC Address: ([0-9A-Fa-f:]{17})\s+\((.*)\)", line)
                if mm:
                    mac = mm.group(1).lower()
                    vendor = mm.group(2).strip()
                    resultados.append((current_ip, mac, vendor))
                    current_ip = None
                elif line.startswith("Host is up"):
                    resultados.append((current_ip, None, None))
                    current_ip = None
        return resultados
    except Exception as e:
        print("⚠️ fallo nmap:", e)
        return resultados

# ---------------- scapy ARP scan (por interfaz) ----------------
def scapy_arp_scan_for_iface(red, iface, timeout=2, inter=0.0):
    if not SCAPY_AVAILABLE:
        return []
    try:
        conf.iface = iface
    except Exception:
        pass
    conf.verb = 0
    targets = [str(ip) for ip in red.hosts()]
    if not targets:
        return []
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=",".join(targets))
        ans, _ = srp(pkt, iface=iface, timeout=timeout, inter=inter)
        resultados = []
        for snd, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.lower()
            resultados.append((ip, mac))
        return resultados
    except Exception as e:
        print(f"⚠️ scapy_arp_scan fallo en {iface}:", e)
        return []

# ---------------- ping y arping helpers ----------------
def ping_host(ip, timeout=TIEMPO_ESPERA_PING):
    try:
        res = subprocess.run(["ping", "-c", "1", "-w", str(timeout), ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def arping_forzar(ip, iface):
    arping_bin = shutil.which("arping")
    if not arping_bin:
        return False
    try:
        subprocess.run([arping_bin, "-c", "1", "-I", iface, ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False

# ---------------- Persistencia / logging ----------------
def _atomic_write(path: Path, data: bytes):
    tmp = None
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
        tmp = Path(tmp_path)
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(data)
        tmp.replace(path)
    finally:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass

def guardar_estado_atomic(estado_list):
    try:
        with estado_lock:
            data = json.dumps(estado_list, ensure_ascii=False, indent=2).encode("utf-8")
            _atomic_write(ESTADO_FILE, data)
    except Exception as e:
        print("⚠️ Error al guardar estado:", e)

def cargar_estado():
    try:
        if ESTADO_FILE.exists():
            with ESTADO_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for d in data:
                        if 'online' not in d:
                            d['online'] = True
                    return data
    except Exception as e:
        print("⚠️ Error al cargar estado:", e)
    return []

def registrar_evento(event):
    try:
        if 'timestamp' not in event:
            event['timestamp'] = ahora_madrid_iso()
        event['timestamp_utc'] = ahora_utc_iso_z()
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with estado_lock:
            with EVENT_LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        print("⚠️ Error al registrar evento:", e)

# ---------------- Escaneo principal (multi-interfaz) ----------------
def escanear_red():
    global dispositivos, nuevos_detectados, desconectados, ultima_ips, ultima_actualizacion
    try:
        lista_dispositivos = []

        interfaces_disponibles = []
        for iface in INTERFACES:
            if interfaz_existe(iface):
                ip = obtener_ip_de_interfaz(iface)
                mask = obtener_mascara_de_interfaz(iface)
                if ip and mask:
                    try:
                        red = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        interfaces_disponibles.append((iface, ip, red))
                    except Exception:
                        continue

        if not interfaces_disponibles:
            print("⚠️ Ninguna interfaz válida (eth0/wlan0) encontrada con IP. Abortando escaneo.")
            return

        tabla_arp_global = leer_tabla_arp()
        now_iso_utc = ahora_utc_iso_z()
        resultados_por_ip = {}

        # === ESCANEO PRINCIPAL ===
        for iface, iface_ip, red in interfaces_disponibles:
            scapy_result = []
            if SCAPY_AVAILABLE:
                scapy_result = scapy_arp_scan_for_iface(red, iface, timeout=2, inter=0.0)
            mapa_scapy = {ip: mac for ip, mac in scapy_result}
            mapa_nmap = {}
            for ip, mac, vendor in escanear_con_nmap(red):
                mapa_nmap[ip] = (mac, vendor)

            for ip in (str(h) for h in red.hosts()):
                mac = None
                vendor = None
                source = None

                # --- Prioridad: router principal (.1) ---
                if ip.endswith(".1"):
                    mac = (
                        tabla_arp_global.get(ip)
                        or mapa_scapy.get(ip)
                        or (mapa_nmap.get(ip)[0] if ip in mapa_nmap else None)
                    )
                    resultados_por_ip[ip] = {
                        "ip": ip,
                        "mac": mac or "Desconocida",
                        "host": "Router principal",
                        "tipo": "Router",
                        "icono": "🏠",
                        "color": "#dc143c",
                        "fabricante": "Router principal",
                        "first_seen": now_iso_utc,
                        "last_seen": now_iso_utc,
                        "seen_count": 1,
                        "_src": f"ip_router@{iface}",
                        "_iface": iface
                    }
                    continue
                # --- Fin router prioritario ---

                # Identificación normal (MAC/OUI)
                if ip in mapa_scapy:
                    mac = mapa_scapy[ip]
                    vendor = get_vendor(mac)
                    source = f"scapy@{iface}"
                elif ip in mapa_nmap:
                    mac, vendor = mapa_nmap[ip]
                    if mac:
                        mac = mac.lower()
                    else:
                        mac = tabla_arp_global.get(ip)
                    vendor = vendor or get_vendor(mac)
                    source = f"nmap@{iface}"
                else:
                    mac = tabla_arp_global.get(ip)
                    if mac:
                        vendor = get_vendor(mac)
                        source = f"arp_table"

                if mac:
                    tipo, icono, color, fabricante = infer_type_from_vendor(vendor, mac)
                    prev = resultados_por_ip.get(ip)
                    prefer = False
                    if not prev:
                        prefer = True
                    else:
                        order = {"ip_router": 4, "scapy": 3, "nmap": 2, "arp_table": 1}
                        prev_src = prev.get("_src", "arp_table").split("@")[0]
                        cur_src = (source or "arp_table").split("@")[0]
                        if order.get(cur_src, 0) > order.get(prev_src, 0):
                            prefer = True
                    if prefer:
                        resultados_por_ip[ip] = {
                            "ip": ip,
                            "mac": mac,
                            "host": fabricante,
                            "tipo": tipo,
                            "icono": icono,
                            "color": color,
                            "fabricante": fabricante,
                            "first_seen": now_iso_utc,
                            "last_seen": now_iso_utc,
                            "seen_count": 1,
                            "_src": source or "arp_table",
                            "_iface": iface
                        }

        # Escaneo complementario
        ips_pendientes = []
        for iface, iface_ip, red in interfaces_disponibles:
            for h in red.hosts():
                ip = str(h)
                if ip not in resultados_por_ip:
                    ips_pendientes.append((ip, iface))

        arping_available = shutil.which("arping") is not None

        def probar_ip_tuple(ip_iface):
            ip, iface = ip_iface
            if ping_host(ip, timeout=TIEMPO_ESPERA_PING):
                if arping_available:
                    arping_forzar(ip, iface)
                tabla_local = leer_tabla_arp()
                mac = tabla_local.get(ip)
                if mac:
                    vendor = get_vendor(mac)
                    tipo, icono, color, fabricante = infer_type_from_vendor(vendor, mac)
                    return {
                        "ip": ip,
                        "mac": mac,
                        "host": fabricante,
                        "tipo": tipo,
                        "icono": icono,
                        "color": color,
                        "fabricante": fabricante,
                        "first_seen": ahora_utc_iso_z(),
                        "last_seen": ahora_utc_iso_z(),
                        "seen_count": 1,
                        "_src": "ping+arping",
                        "_iface": iface
                    }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
            futuros = [ex.submit(probar_ip_tuple, ip_iface) for ip_iface in ips_pendientes]
            for fut in concurrent.futures.as_completed(futuros, timeout=300):
                try:
                    res = fut.result()
                    if res:
                        ip = res['ip']
                        if ip not in resultados_por_ip:
                            resultados_por_ip[ip] = res
                except Exception:
                    pass

        # Consolidar resultados
        lista_dispositivos = []
        for ip, d in resultados_por_ip.items():
            d_clean = {
                "ip": d["ip"],
                "mac": d.get("mac", "Desconocida"),
                "host": d.get("host"),
                "tipo": d.get("tipo"),
                "icono": d.get("icono"),
                "color": d.get("color"),
                "fabricante": d.get("fabricante"),
                "first_seen": d.get("first_seen", now_iso_utc),
                "last_seen": ahora_utc_iso_z(),
                "seen_count": d.get("seen_count", 1)
            }
            lista_dispositivos.append(d_clean)

        # === PERSISTENCIA Y EVENTOS ===
        estado_anterior = cargar_estado()
        mapa_anterior = {d['ip']: d for d in estado_anterior if 'ip' in d}
        mapa_actual = {}

        for d in lista_dispositivos:
            ip = d['ip']
            mac = d.get('mac')
            if ip in mapa_anterior:
                prev = mapa_anterior[ip]
                d['first_seen'] = prev.get('first_seen', d['first_seen'])
                d['seen_count'] = prev.get('seen_count', 0) + 1
                prev_mac = prev.get('mac')
                if prev_mac and prev_mac != mac:
                    registrar_evento({
                        "ip": ip,
                        "mac": mac,
                        "tipo": "mac_cambiada",
                        "detalle": {"antes": prev_mac, "ahora": mac}
                    })
            d['last_seen'] = ahora_utc_iso_z()
            d['online'] = True
            mapa_actual[ip] = d

        # Incluir equipo rastreador
        for iface, iface_ip, _ in interfaces_disponibles:
            try:
                local_ip = iface_ip
                local_mac = obtener_mac_interfaz(iface)
                if local_ip:
                    vendor_local = get_vendor(local_mac) if local_mac else None
                    tipo_local, icono_local, color_local, fabricante_local = infer_type_from_vendor(vendor_local, local_mac)
                    nombre_local = f"Equipo rastreador ({iface})"
                    if local_ip not in mapa_actual and local_mac:
                        mapa_actual[local_ip] = {
                            "ip": local_ip,
                            "mac": local_mac,
                            "host": nombre_local,
                            "tipo": tipo_local,
                            "icono": icono_local,
                            "color": color_local,
                            "fabricante": fabricante_local,
                            "first_seen": now_iso_utc,
                            "last_seen": ahora_utc_iso_z(),
                            "seen_count": 1,
                            "online": True
                        }
                    elif local_ip in mapa_actual:
                        mapa_actual[local_ip]['host'] = nombre_local
            except Exception:
                pass

        # Marcar desconectados
        for ip, prev in mapa_anterior.items():
            if ip not in mapa_actual:
                off = prev.copy()
                off['online'] = False
                mapa_actual[ip] = off

        actuales = {ip for ip, d in mapa_actual.items() if d.get('online')}
        prev_online = {ip for ip, d in mapa_anterior.items() if d.get('online', True)}
        nuevos = actuales - prev_online
        descon = prev_online - actuales

        nuevos_detectados[:] = [mapa_actual[ip] for ip in nuevos]
        desconectados[:] = [mapa_actual[ip] for ip in mapa_actual if not mapa_actual[ip].get('online')]

        for ip in nuevos:
            d = mapa_actual[ip]
            registrar_evento({"ip": ip, "mac": d.get('mac'), "tipo": "nuevo", "detalle": {"fabricante": d.get('fabricante')}})
        for ip in descon:
            d = mapa_anterior.get(ip, {})
            registrar_evento({"ip": ip, "mac": d.get('mac'), "tipo": "desconectado", "detalle": {"last_seen": d.get('last_seen')}})

        # === ORDEN: Router primero ===
        dispositivos_final = sorted(
            [d for d in mapa_actual.values() if d.get('online')],
            key=lambda d: (0 if d.get('tipo') == "Router" else 1, ipaddress.IPv4Address(d['ip']))
        )

        dispositivos[:] = dispositivos_final
        ultima_ips.clear()
        ultima_ips.update(actuales)
        ultima_actualizacion = time.strftime("%Y-%m-%d %H:%M:%S")

        guardar_estado_atomic(sorted(mapa_actual.values(), key=lambda d: ipaddress.IPv4Address(d['ip'])))
        print(f"✅ Escaneo terminado ({ultima_actualizacion}). {len(dispositivos)} activos.")

    except Exception as e:
        print("⚠️ Error crítico en escaneo:", e)

def hilo_seguro():
    while True:
        try:
            escanear_red()
        except Exception as e:
            print("⚠️ Error en hilo de escaneo:", e)
        time.sleep(INTERVALO_ESCANEO)

# ---------------- Flask Dashboard ----------------
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
    except Exception as e:
        print("⚠️ Error al leer credenciales:", e)
    return usuario, password

AUTH_USERNAME, AUTH_PASSWORD = cargar_credenciales()
if not AUTH_USERNAME or not AUTH_PASSWORD:
    print("⚠️ No se pudieron cargar credenciales válidas desde credservpas.xk. Se usarán las por defecto.")
    AUTH_USERNAME = "admin"
    AUTH_PASSWORD = "admin"

def _check_auth(username, password):
    return username == AUTH_USERNAME and password == AUTH_PASSWORD

def _authenticate():
    return Response(
        'Acceso requerido', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

@app.before_request
def proteger():
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return _authenticate()

# ---------------- Rutas ----------------
@app.route("/")
def dashboard():
    tabla = ""
    for d in dispositivos:
        # destacar la fila si es router
        tr_style = "class='router-row'" if d.get('tipo') == "Router" else ""
        ip_cell_style = 'style="color:#dc143c;font-weight:bold;"' if d.get('tipo') == "Router" else ""
        tabla += (
            f"<tr {tr_style}>"
            f"<td style='font-size:1.4em'>{d.get('icono','')}</td>"
            f"<td {ip_cell_style}>{d.get('ip')}</td>"
            f"<td {ip_cell_style}>{d.get('mac')}</td>"
            f"<td {ip_cell_style}>{d.get('host')}</td>"
            f"<td {ip_cell_style}>{d.get('tipo')}</td>"
            f"<td>{convertir_a_horario_españa(d.get('last_seen',''))}</td>"
            f"<td>{d.get('seen_count',0)}</td>"
            f"</tr>"
        )

    alerta_nuevos = "".join(
        f"<li style='color:{d.get('color','#000')}; font-weight:bold'>{d.get('ip')} - {d.get('mac')} - {d.get('fabricante')} - {d.get('tipo')} {d.get('icono')}</li>"
        for d in nuevos_detectados
    )

    # deduplicar desconectados por MAC (mantener el last_seen más reciente) y ocultar IP en la vista
    unique_by_mac = {}
    for d in desconectados:
        mac = d.get('mac')
        if not mac:
            continue
        mac_c = canonical_mac(mac)
        prev = unique_by_mac.get(mac_c)
        if not prev:
            unique_by_mac[mac_c] = d
        else:
            ls_new = d.get('last_seen')
            ls_prev = prev.get('last_seen')
            try:
                if ls_new and ls_prev:
                    if ls_new > ls_prev:
                        unique_by_mac[mac_c] = d
                elif ls_new and not ls_prev:
                    unique_by_mac[mac_c] = d
            except Exception:
                pass
    unique_desconectados = list(unique_by_mac.values())

    alerta_desconectados = "".join(
        f"<li style='color:red; font-weight:bold'>{d.get('mac')} - {d.get('fabricante')} - {d.get('tipo')} ❌ Desconectado (última vez: {convertir_a_horario_españa(d.get('last_seen',''))})</li>"
        for d in unique_desconectados
    )

    # Plantilla HTML integrada (resaltamos router, mostramos tabla con router primero porque escanear_red lo ordena así)
    return render_template_string("""
    <html lang="es">
    <head>
        <meta http-equiv="refresh" content="10">
        <title>Escaneo de red (Scapy ARP + Persistencia)</title>
        <style>
            body { font-family: Arial; margin: 20px; background-color: #f8f9fa; }
            header { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
            h1 { margin:0; font-size:1.2em; }
            .top-right-btn { position: fixed; top: 12px; right: 12px; z-index: 999; }
            .top-right-btn form, .top-right-btn a { margin-left:6px; display:inline-block; vertical-align:middle; }
            .top-right-btn .btn { padding:8px 10px; font-size:0.9em; cursor:pointer; }
            table { border-collapse: collapse; width: 95%; background-color: white; margin-top:6px; }
            th, td { border: 1px solid #999; padding: 6px; text-align: center; font-size: 0.9em; }
            th { background-color: #e9ecef; }
            ul { list-style-type: none; padding-left: 0; }
            .timestamp { margin-top: 10px; font-size: 0.9em; color: #555; }
            .small { font-size: 0.8em; color: #666; }
            .btn { padding:8px 10px; font-size:0.9em; cursor:pointer; background:#007bff; color:white; border:none; border-radius:3px; }
            .btn-secondary { background:#6c757d; }
            .router-row { background-color: #ffecec; }
        </style>
    </head>
    <body>
        <header>
            <h1>📡 Dispositivos activos · {{ app_display_name }}</h1>
            <div class="top-right-btn">
                <form action="{{ url_for('cambiar_credenciales') }}" method="get" style="display:inline;">
                    <button class="btn" type="submit">🔑 Cambiar usuario/contraseña</button>
                </form>
                <a href="{{ url_for('editar_tipos') }}" style="text-decoration:none;">
                    <button class="btn btn-secondary" type="button">🧩 Configurar tipos de equipos</button>
                </a>
            </div>
        </header>

        <table>
            <tr><th>Icono</th><th>IP</th><th>MAC</th><th>Host / Fabricante</th><th>Tipo</th><th>Última vez visto</th><th>Veces visto</th></tr>
            {{ tabla|safe }}
        </table>

        <h3>🚨 Nuevos detectados</h3>
        <ul>{{ alerta_nuevos|safe }}</ul>

        <h3>❌ Desconectados (conocidos)</h3>
        <ul>{{ alerta_desconectados|safe }}</ul>

        <div class="timestamp">🕒 Último escaneo: {{ ultima_actualizacion }}</div>
        <p class="small">🔄 Esta página se actualiza automáticamente cada 10 segundos. Scapy: {{ scapy_ok }}</p>
        <p class="small">📁 Estado: {{ estado_file }} · 📜 Log: {{ log_file }} · 🧩 <a href="{{ url_for('editar_tipos') }}">Editar reglas de tipos</a></p>

        <h4 class="small" style="margin-top:12px;">{{ app_display_name }}</h4>
        <p class="small">B174M3 // XaeK</p>
    </body>
    </html>
    """, tabla=tabla, alerta_nuevos=alerta_nuevos, alerta_desconectados=alerta_desconectados,
       ultima_actualizacion=ultima_actualizacion, scapy_ok=SCAPY_AVAILABLE,
       estado_file=str(ESTADO_FILE), log_file=str(EVENT_LOG_FILE),
       app_display_name=APP_DISPLAY_NAME)

@app.route("/tipos", methods=["GET"])
def editar_tipos():
    # mostrar editor
    tipos = cargar_tipos()
    # Renderizamos página que permite editar fácil las reglas
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <title>Editor de Tipos de Dispositivo</title>
      <style>
        body { font-family: Arial; margin: 24px; background: #f7f7f7; }
        table { border-collapse: collapse; width: 100%; background: white; margin-top:12px; }
        th, td { padding: 8px; border: 1px solid #ccc; text-align: center; }
        th { background: #333; color: white; }
        button { padding: 6px 12px; cursor: pointer; border: none; border-radius:4px; }
        .add-row { margin: 10px 0; background: #28a745; color: white; }
        .save { margin-top: 20px; background: #007bff; color: white; }
        .delete { background: #dc3545; color: white; }
        input[type="text"] { width: 95%; padding:6px; box-sizing:border-box; }
        .top { display:flex; align-items:center; justify-content:space-between; gap:12px; }
        a { text-decoration:none; color:#007bff; }
      </style>
    </head>
    <body>
      <div class="top">
        <div>
          <h2>⚙️ Configuración de detección de dispositivos</h2>
          <p>Introduce palabras clave separadas por comas (busca en fabricante/OUI). Ej: <code>apple,iphone,ipad,mac</code></p>
        </div>
        <div>
          <a href="{{ url_for('dashboard') }}">⬅️ Volver al panel</a>
        </div>
      </div>

      <table id="tabla">
        <thead>
          <tr>
            <th>Palabras clave (separadas por comas)</th>
            <th>Tipo</th>
            <th>Icono</th>
            <th>Color</th>
            <th>Eliminar</th>
          </tr>
        </thead>
        <tbody>
          {% for t in tipos %}
          <tr>
            <td><input type="text" value="{{ ','.join(t.keywords) }}"></td>
            <td><input type="text" value="{{ t.tipo }}"></td>
            <td><input type="text" value="{{ t.icono }}"></td>
            <td><input type="text" value="{{ t.color }}"></td>
            <td><button class="delete" onclick="eliminarFila(this)">🗑️</button></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>

      <button class="add-row" onclick="agregarFila()">➕ Añadir nueva regla</button>
      <button class="save" onclick="guardar()">💾 Guardar cambios</button>

      <script>
        function agregarFila() {
          const t = document.querySelector("#tabla tbody");
          const row = document.createElement("tr");
          row.innerHTML = `<td><input type="text" value=""></td>
                           <td><input type="text" value=""></td>
                           <td><input type="text" value=""></td>
                           <td><input type="text" value=""></td>
                           <td><button class="delete" onclick="eliminarFila(this)">🗑️</button></td>`;
          t.appendChild(row);
        }
        function eliminarFila(btn) {
          btn.closest("tr").remove();
        }
        async function guardar() {
          const filas = document.querySelectorAll("#tabla tbody tr");
          const tipos = [];
          filas.forEach(tr => {
            const inputs = tr.querySelectorAll("input[type='text']");
            const palabras = inputs[0].value.split(",").map(x => x.trim()).filter(Boolean);
            const tipo = inputs[1].value.trim();
            const icono = inputs[2].value.trim();
            const color = inputs[3].value.trim();
            if (palabras.length && tipo)
              tipos.push({keywords: palabras, tipo, icono, color});
          });
          try {
            const r = await fetch("{{ url_for('guardar_tipos') }}", {
              method: "POST",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({tipos})
            });
            if (r.ok) {
              alert("✅ Cambios guardados correctamente");
              window.location.href = "{{ url_for('dashboard') }}";
            } else {
              alert("⚠️ Error al guardar");
            }
          } catch (e) {
            alert("⚠️ Error de conexión: " + e);
          }
        }
      </script>
    </body>
    </html>
    """, tipos=TIPOS)

@app.route("/tipos/guardar", methods=["POST"])
def guardar_tipos_route():
    try:
        data = request.get_json(force=True)
        tipos_nuevos = data.get("tipos", [])
        # Validación ligera: cada entrada debe tener keywords (lista) y tipo
        cleaned = []
        for t in tipos_nuevos:
            kw = t.get("keywords") or []
            tipo = t.get("tipo","").strip()
            icono = t.get("icono","").strip()
            color = t.get("color","").strip()
            if not isinstance(kw, list) or not tipo:
                continue
            cleaned.append({"keywords": [str(k).strip().lower() for k in kw if str(k).strip()], "tipo": tipo, "icono": icono, "color": color})
        ok = guardar_tipos(cleaned)
        if ok:
            global TIPOS
            with tipos_lock:
                TIPOS = cleaned
            registrar_evento({"tipo":"tipos_actualizados","detalle":{"count": len(cleaned), "by": request.authorization.username if request.authorization else None}})
            return jsonify({"ok": True}), 200
    except Exception as e:
        print("Error guardando tipos:", e)
    return jsonify({"ok": False}), 500

# alias route más amigable usada por JS
@app.route("/guardar_tipos", methods=["POST"])
def guardar_tipos():
    return guardar_tipos_route()

# ---------------- Helper: reinicio en background ----------------
def _background_restart_service(cmd_list):
    """Ejecuta el comando de reinicio en un hilo separado y lo registra en el log."""
    try:
        registrar_evento({"tipo":"restart_attempt","detalle":{"cmd":" ".join(cmd_list), "timestamp": ahora_madrid_iso()}})
        p = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, text=True)
        registrar_evento({"tipo":"restart_result","detalle":{"cmd":" ".join(cmd_list),
                                                           "returncode": p.returncode,
                                                           "stdout": p.stdout,
                                                           "stderr": p.stderr,
                                                           "timestamp": ahora_madrid_iso()}})
    except Exception as e:
        registrar_evento({"tipo":"restart_exception","detalle":{"err": str(e), "timestamp": ahora_madrid_iso()}})

# ---------------- Cambio de credenciales (con confirmación) ----------------
@app.route("/cambiar_credenciales", methods=["GET", "POST"])
def cambiar_credenciales():
    auth = request.authorization
    current_user = auth.username if auth else None

    if request.method == "POST":
        user_actual = request.form.get("user_actual", "").strip()
        pass_actual = request.form.get("pass_actual", "").strip()
        new_user = request.form.get("new_user", "").strip()
        new_pass = request.form.get("new_pass", "")
        confirm_pass = request.form.get("confirm_pass", "")

        error = None
        if not user_actual or not pass_actual or not new_user or not new_pass or not confirm_pass:
            error = "Todos los campos son obligatorios."
        elif not _check_auth(user_actual, pass_actual):
            error = "Credenciales actuales incorrectas."
        elif new_pass != confirm_pass:
            error = "La nueva contraseña y su confirmación no coinciden."
        if error:
            return render_template_string("""
                <h3 style="color:red">{{ error }}</h3>
                <p><a href="{{ url_for('cambiar_credenciales') }}">Volver</a></p>
            """, error=error)

        try:
            data = f"{new_user}\n{new_pass}\n".encode("utf-8")
            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(CRED_FILE.parent))
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(data)
            os.replace(tmp_path, str(CRED_FILE))
            try:
                os.chmod(CRED_FILE, 0o600)
            except Exception:
                pass
        except Exception as e:
            return render_template_string("""
                <h3 style="color:red">Error escribiendo el fichero de credenciales: {{ err }}</h3>
                <p><a href="{{ url_for('dashboard') }}">Volver al panel</a></p>
            """, err=str(e))

        registrar_evento({
            "tipo": "credenciales_cambiadas",
            "detalle": {"by": user_actual, "timestamp": ahora_madrid_iso()}
        })
        global AUTH_USERNAME, AUTH_PASSWORD
        AUTH_USERNAME, AUTH_PASSWORD = new_user, new_pass

        if os.geteuid() == 0:
            cmd = ["systemctl", "restart", SERVICE_NAME]
        else:
            cmd = ["sudo", "systemctl", "restart", SERVICE_NAME]

        th = threading.Thread(target=_background_restart_service, args=(cmd,), daemon=True)
        th.start()

        return render_template_string("""
        <html lang="es">
        <head>
          <meta charset="utf-8">
          <meta http-equiv="refresh" content="5;url={{ url_for('dashboard') }}">
          <title>Credenciales actualizadas</title>
          <style>
            body { font-family: Arial; margin: 20px; text-align: center; }
            pre { background:#f3f3f3; padding:8px; border-radius:4px; display:inline-block; text-align:left; max-width:90%; overflow:auto; }
            .ok { color: green; }
            .note { color: #555; margin-top:8px; }
            .btn { padding:8px 10px; display:inline-block; margin-top:12px; }
          </style>
          <script>
            setTimeout(function(){
              window.location.href = "{{ url_for('dashboard') }}";
            }, 5000);
          </script>
        </head>
        <body>
          <h2>🔐 Credenciales actualizadas</h2>
          <p class="ok">Se han guardado las nuevas credenciales. El servicio se está reiniciando en segundo plano.</p>
          <p class="note">Serás redirigido automáticamente al panel principal en 5 segundos.</p>
          <p>Si no te redirige, <a href="{{ url_for('dashboard') }}">pulsa aquí</a>.</p>
        </body>
        </html>
        """)

    return render_template_string("""
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <title>Cambiar credenciales</title>
      <style>
        body { font-family: Arial; margin: 20px; }
        label { display:block; margin-top:8px; }
        input { padding:6px; width:320px; }
        .btn { margin-top:12px; padding:8px 12px; }
      </style>
    </head>
    <body>
      <h2>🔑 Cambiar usuario/contraseña</h2>
      <p>Confirma las credenciales actuales y escribe las nuevas.</p>
      <p><b>OJO, DISTINGUE MAYUSCULAS/minusculas TANTO EN EL USUARIO COMO EN LA CONTRASEÑA</b></p></br>
      <form method="post" onsubmit="return confirm('¿Seguro que quieres guardar y reiniciar el servicio?');">
        <label>Usuario actual:<br><input type="text" name="user_actual" required></label>
        <label>Contraseña actual:<br><input type="password" name="pass_actual" required></label>
        <hr>
        <label>Nuevo usuario:<br><input type="text" name="new_user" required></label>
        <label>Nueva contraseña:<br><input type="password" name="new_pass" required></label>
        <label>Confirmar nueva contraseña:<br><input type="password" name="confirm_pass" required></label>
        <button class="btn" type="submit">Guardar y reiniciar servicio</button>
      </form>
      <p><a href="{{ url_for('dashboard') }}">⬅️ Volver</a></p>
    </body>
    </html>
    """)

# ---------------- main ----------------
if __name__ == "__main__":
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # cargar estado previo y tipos
    estado_inicial = cargar_estado()
    dispositivos = [d for d in estado_inicial if d.get('online')]
    ultima_ips = set(d['ip'] for d in dispositivos if 'ip' in d)
    # TIPOS ya cargado en la definición global (cargar_tipos)

    if not SCAPY_AVAILABLE:
        print("⚠️ Scapy no está disponible. Instala scapy: sudo pip3 install scapy")
    else:
        print("🛠 Scapy listo: usando ARP masivo para detección rápida.")

    print(f"🔎 Iniciando escaneo automático (INTERFACES={INTERFACES}). Estado cargado: {len(estado_inicial)} dispositivos (online: {len(dispositivos)}).")
    threading.Thread(target=hilo_seguro, daemon=True).start()
    # Nota: en producción usa un WSGI server (gunicorn, systemd) para mayor robustez.
    app.run(host="0.0.0.0", port=5000)