#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de red completo (Scapy ARP masivo) + nmap + arping + ping.
Persistencia de estado + historial de eventos (JSONL).
Incluye UI para cambiar credenciales y reiniciar el servicio.
Soporta edición web de reglas (tipos.json) y asignaciones exactas por MAC (macs.json).
Ejecutar como root: sudo python3 scanner_scapy_persist_final.py
"""

import time
import threading
import socket
import re
import ipaddress
from pathlib import Path
import shutil
import subprocess
import concurrent.futures
from flask import Flask, render_template_string, request, Response, url_for
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
OUI_FILE = BASE_DIR / "oui.txt"                        # fichero OUI local (opcional)
CRED_FILE = BASE_DIR / "credservpas.xk"
TIPOS_FILE = BASE_DIR / "tipos.json"
MACS_FILE = BASE_DIR / "macs.json"

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
macs_lock = threading.Lock()

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

# ---------------- Tipos y MACs (persistentes y editables) ----------------
def crear_tipos_por_defecto():
    return [
        {"keywords": ["apple", "iphone", "ipad", "mac"], "tipo":"iPhone/iPad/AppleTV", "icono":"📱", "color":"#fbbc04"},
        {"keywords": ["hewlett","hp","dell","lenovo","asus","mitac","intel"], "tipo":"PC/Laptop", "icono":"💻", "color":"#4285f4"},
        {"keywords": ["raspberry","b8:27:eb","dc:a6:32"], "tipo":"Raspberry Pi", "icono":"🍓", "color":"#f28b82"},
        {"keywords": ["tct","tp-link","netgear","tenda","huawei","zte"], "tipo":"Router", "icono":"📶", "color":"#dc143c"},
        {"keywords": ["epson","canon","brother","printer"], "tipo":"Impresora", "icono":"🖨️", "color":"#a142f4"},
        {"keywords": ["espressif","esp8266","esp32","sonoff"], "tipo":"IoT/SmartDevice", "icono":"🔌", "color":"#6a5acd"},
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
    # guardar por defecto si no existe
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

def cargar_macs(ruta=MACS_FILE):
    try:
        if ruta.exists():
            with ruta.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # normalizar claves a minúsculas
                    return {k.lower(): v for k, v in data.items()}
    except Exception:
        pass
    return {}

def guardar_macs(data, ruta=MACS_FILE):
    try:
        with macs_lock:
            with ruta.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def infer_type_from_vendor(vendor, mac):
    """
    Return tipo, icono, color, fabricante_display
    Prioridad:
     1) MAC exacta en macs.json
     2) IP .1 special router handling done earlier (so not here)
     3) tipos.json keyword match against vendor or mac
     4) heuristics
    """
    mac_l = (mac or "").lower()
    macs = cargar_macs()
    if mac_l and mac_l in macs:
        entry = macs[mac_l]
        nombre = entry.get("nombre") or entry.get("tipo") or "Conocido"
        return entry.get("tipo", nombre), entry.get("icono", "❓"), entry.get("color", "#aaaaaa"), entry.get("nombre", nombre)

    v = (vendor or "").lower()
    tipos = cargar_tipos()
    for regla in tipos:
        palabras = [p.strip().lower() for p in regla.get("keywords", [])]
        for palabra in palabras:
            if palabra and (palabra in v or palabra in mac_l):
                return regla.get("tipo", "Desconocido"), regla.get("icono", "❓"), regla.get("color", "#aaaaaa"), vendor or regla.get("tipo")
    # heuristics
    if mac_l and (mac_l.startswith("b8:27:eb") or mac_l.startswith("dc:a6:32")):
        return "Raspberry Pi", "🍓", "#f28b82", "Raspberry"
    if "apple" in v or "iphone" in v:
        return "iPhone/iPad/AppleTV", "📱/📺️", "#fbbc04", vendor
    if "samsung" in v or "xiaomi" in v or "huawei" in v:
        return "Android", "🤖", "#34a853", vendor
    return "Desconocido", "❓", "#aaaaaa", vendor or "Desconocido"

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
            print("⚠️ Ninguna interfaz válida encontrada con IP. Abortando escaneo.")
            return

        tabla_arp_global = leer_tabla_arp()

        now_iso_utc = ahora_utc_iso_z()
        resultados_por_ip = {}

        # 1) Scaneo por interfaz: scapy, luego nmap, luego arp table
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
                    tipo, icono, color, fabricante = "Router", "🏠", "#dc143c", "Router principal"
                    resultados_por_ip[ip] = {
                        "ip": ip,
                        "mac": mac or "Desconocida",
                        "host": "Router principal",
                        "tipo": tipo,
                        "icono": icono,
                        "color": color,
                        "fabricante": fabricante,
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
                    prefer_current = False
                    if not prev:
                        prefer_current = True
                    else:
                        order = {"scapy":3, "nmap":2, "arp_table":1}
                        prev_src = prev.get('_src','arp_table').split('@')[0]
                        cur_src = (source or 'arp_table').split('@')[0]
                        if order.get(cur_src,0) > order.get(prev_src,0):
                            prefer_current = True
                    if prefer_current:
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

        # 2) Completar con ping+arping para hosts pendientes
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
        for iface, iface_ip, red in interfaces_disponibles:
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
                        if local_mac and not mapa_actual[local_ip].get('mac'):
                            mapa_actual[local_ip]['mac'] = local_mac
                            mapa_actual[local_ip]['fabricante'] = fabricante_local
                        mapa_actual[local_ip]['host'] = nombre_local
                        mapa_actual[local_ip]['tipo'] = tipo_local
                        mapa_actual[local_ip]['icono'] = icono_local
                        mapa_actual[local_ip]['color'] = color_local
            except Exception:
                pass

        # Marcar desconectados
        for ip, prev in mapa_anterior.items():
            if ip not in mapa_actual:
                offline_entry = prev.copy()
                offline_entry['online'] = False
                mapa_actual[ip] = offline_entry

        actuales_ips = {ip for ip, d in mapa_actual.items() if d.get('online')}
        prev_ips_online = {ip for ip, d in mapa_anterior.items() if d.get('online', True)}
        nuevos = actuales_ips - prev_ips_online
        descon = prev_ips_online - actuales_ips

        nuevos_detectados[:] = [mapa_actual[ip] for ip in nuevos]
        desconectados[:] = [mapa_actual[ip] for ip in mapa_actual if not mapa_actual[ip].get('online')]

        for ip in nuevos:
            d = mapa_actual[ip]
            registrar_evento({
                "ip": ip,
                "mac": d.get('mac'),
                "tipo": "nuevo",
                "detalle": {"fabricante": d.get('fabricante'), "tipo": d.get('tipo')}
            })
        for ip in descon:
            d = mapa_anterior.get(ip, {})
            registrar_evento({
                "ip": ip,
                "mac": d.get('mac'),
                "tipo": "desconectado",
                "detalle": {"last_seen": d.get('last_seen')}
            })
        for ip in (actuales_ips & prev_ips_online):
            d = mapa_actual[ip]
            registrar_evento({
                "ip": ip,
                "mac": d.get('mac'),
                "tipo": "visto",
                "detalle": {"last_seen": d.get('last_seen')}
            })

        dispositivos_final = sorted([d for d in mapa_actual.values() if d.get('online')], key=lambda d: ipaddress.IPv4Address(d['ip']))
        # Asegurar router(s) al principio (tipo == "Router")
        dispositivos_final = sorted(dispositivos_final, key=lambda d: (0 if d.get('tipo') == "Router" else 1, ipaddress.IPv4Address(d['ip'])))
        dispositivos[:] = dispositivos_final

        ultima_ips.clear()
        ultima_ips.update(actuales_ips)
        ultima_actualizacion = time.strftime("%Y-%m-%d %H:%M:%S")

        guardar_estado_atomic(sorted(mapa_actual.values(), key=lambda d: ipaddress.IPv4Address(d['ip'])))

        print(f"✅ Escaneo terminado ({ultima_actualizacion}). {len(dispositivos)} activos. Nuevos: {len(nuevos_detectados)}, desconectados ahora: {len([1 for v in mapa_actual.values() if not v.get('online')])}")
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

# ---------------- Rutas: Dashboard ----------------
@app.route("/")
def dashboard():
    tabla = "".join(
        f"<tr style='background-color:{d.get('color','#ffffff')}'>"
        f"<td>{d.get('ip')}</td><td>{d.get('mac')}</td><td>{d.get('host') or ''}</td>"
        f"<td>{d.get('fabricante')}</td><td>{d.get('tipo')}</td><td>{d.get('icono')}</td>"
        f"<td>{convertir_a_horario_españa(d.get('first_seen',''))}</td>"
        f"<td>{convertir_a_horario_españa(d.get('last_seen',''))}</td>"
        f"<td>{d.get('seen_count',0)}</td></tr>"
        for d in dispositivos
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
                    <button class="btn btn-secondary" type="button">🧩 Configurar tipos/MACs</button>
                </a>
            </div>
        </header>

        <table>
            <tr><th>IP</th><th>MAC</th><th>Host</th><th>Fabricante</th><th>Tipo</th><th>Icono</th><th>Visto por primera vez</th><th>Ultima vez visto</th><th>Veces visto</th></tr>
            {{ tabla|safe }}
        </table>

        <h3>🚨 Nuevos detectados</h3>
        <ul>{{ alerta_nuevos|safe }}</ul>

        <h3>❌ Desconectados (conocidos)</h3>
        <ul>{{ alerta_desconectados|safe }}</ul>

        <div class="timestamp">🕒 Último escaneo: {{ ultima_actualizacion }}</div>
        <p class="small">🔄 Esta página se actualiza automáticamente cada 10 segundos. Scapy: {{ scapy_ok }}</p>
        <p class="small">📁 Estado: {{ estado_file }} · 📜 Log: {{ log_file }}</p>

        <h4 class="small" style="margin-top:12px;">{{ app_display_name }}</h4>
        <p class="small">B174M3 // XaeK</p>
    </body>
    </html>
    """, tabla=tabla, alerta_nuevos=alerta_nuevos, alerta_desconectados=alerta_desconectados,
       ultima_actualizacion=ultima_actualizacion, scapy_ok=SCAPY_AVAILABLE,
       estado_file=str(ESTADO_FILE), log_file=str(EVENT_LOG_FILE),
       app_display_name=APP_DISPLAY_NAME)

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

# ---------------- Editor web para tipos y MACs ----------------
EDITOR_HTML = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Editor Tipos y MACs</title>
  <style>
    body{font-family:Arial;margin:20px;background:#f7f7f7}
    table{border-collapse:collapse;background:#fff;width:100%}
    th,td{border:1px solid #ccc;padding:8px;text-align:left}
    th{background:#333;color:#fff}
    input[type="text"]{width:100%; padding:6px; box-sizing:border-box}
    input[type="color"]{height:30px;width:60px;border:none}
    select{font-size:1.1em}
    .row-actions{display:flex;gap:8px;align-items:center}
    .btn{padding:8px 10px;border:none;border-radius:4px;cursor:pointer}
    .btn-save{background:#007bff;color:#fff}
    .btn-add{background:#28a745;color:#fff}
    .btn-del{background:#dc3545;color:#fff}
    .section{margin-bottom:18px}
  </style>
</head>
<body>
  <h2>⚙️ Configuración de detección de dispositivos</h2>
  <div class="section">
    <h3>Reglas (keywords → tipo, icono, color)</h3>
    <p>Ej: <code>apple,iphone,ipad,mac</code> → <code>iPhone/iPad/AppleTV</code></p>
    <table id="tabla-tipos">
      <thead><tr><th>Keywords (coma separados)</th><th>Tipo</th><th>Icono</th><th>Color</th><th>Acción</th></tr></thead>
      <tbody>
        {% for r in tipos %}
        <tr>
          <td><input type="text" class="keywords" value="{{ ','.join(r.keywords) }}"></td>
          <td><input type="text" class="tipo" value="{{ r.tipo }}"></td>
          <td>
            <select class="icono">
              {% for e in emojis %}
                <option value="{{e}}" {% if e==r.icono %}selected{% endif %}>{{e}}</option>
              {% endfor %}
            </select>
          </td>
          <td><input type="color" class="color" value="{{ r.color }}"></td>
          <td><button class="btn btn-del" onclick="eliminarFila(this)">🗑️</button></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div style="margin-top:8px">
      <button class="btn btn-add" onclick="agregarTipo()">➕ Añadir regla</button>
    </div>
  </div>

  <div class="section">
    <h3>MACs exactas (mac → nombre/tipo/icono/color)</h3>
    <p>Introduce la MAC en minúsculas (ej: <code>aa:bb:cc:11:22:33</code>)</p>
    <table id="tabla-macs">
      <thead><tr><th>MAC</th><th>Nombre</th><th>Tipo</th><th>Icono</th><th>Color</th><th>Acción</th></tr></thead>
      <tbody>
        {% for mac,info in macs.items() %}
        <tr>
          <td><input type="text" class="mac" value="{{ mac }}"></td>
          <td><input type="text" class="nombre" value="{{ info.nombre }}"></td>
          <td><input type="text" class="tipo" value="{{ info.tipo }}"></td>
          <td>
            <select class="icono">
              {% for e in emojis %}
                <option value="{{e}}" {% if e==info.icono %}selected{% endif %}>{{e}}</option>
              {% endfor %}
            </select>
          </td>
          <td><input type="color" class="color" value="{{ info.color }}"></td>
          <td><button class="btn btn-del" onclick="eliminarFila(this)">🗑️</button></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div style="margin-top:8px">
      <button class="btn btn-add" onclick="agregarMac()">➕ Añadir MAC</button>
    </div>
  </div>

  <div style="margin-top:18px">
    <button class="btn btn-save" onclick="guardar()">💾 Guardar cambios</button>
    <a href="{{ url_for('dashboard') }}" style="margin-left:12px">⬅️ Volver al panel</a>
  </div>

<script>
const EMOJIS = {{ emojis|tojson }};

function agregarTipo(){
  const tb = document.querySelector("#tabla-tipos tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `<td><input type="text" class="keywords"></td>
                  <td><input type="text" class="tipo"></td>
                  <td><select class="icono">${EMOJIS.map(e=>`<option value="${e}">${e}</option>`).join('')}</select></td>
                  <td><input type="color" class="color" value="#999999"></td>
                  <td><button class="btn btn-del" onclick="eliminarFila(this)">🗑️</button></td>`;
  tb.appendChild(tr);
}

function agregarMac(){
  const tb = document.querySelector("#tabla-macs tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `<td><input type="text" class="mac" value=""></td>
                  <td><input type="text" class="nombre" value=""></td>
                  <td><input type="text" class="tipo" value=""></td>
                  <td><select class="icono">${EMOJIS.map(e=>`<option value="${e}">${e}</option>`).join('')}</select></td>
                  <td><input type="color" class="color" value="#999999"></td>
                  <td><button class="btn btn-del" onclick="eliminarFila(this)">🗑️</button></td>`;
  tb.appendChild(tr);
}

function eliminarFila(btn){
  btn.closest("tr").remove();
}

async function guardar(){
  // tipos
  const tipos = [];
  document.querySelectorAll("#tabla-tipos tbody tr").forEach(tr=>{
    const keys = tr.querySelector(".keywords").value.split(",").map(s=>s.trim()).filter(Boolean);
    const tipo = tr.querySelector(".tipo").value.trim();
    const icono = tr.querySelector(".icono").value;
    const color = tr.querySelector(".color").value;
    if(keys.length && tipo){
      tipos.push({keywords: keys, tipo: tipo, icono: icono, color: color});
    }
  });
  // macs
  const macs = {};
  document.querySelectorAll("#tabla-macs tbody tr").forEach(tr=>{
    const mac = tr.querySelector(".mac").value.trim().toLowerCase();
    const nombre = tr.querySelector(".nombre").value.trim();
    const tipo = tr.querySelector(".tipo").value.trim();
    const icono = tr.querySelector(".icono").value;
    const color = tr.querySelector(".color").value;
    if(mac){
      macs[mac] = {nombre: nombre||tipo, tipo: tipo||nombre, icono: icono, color: color};
    }
  });

  const resp = await fetch("{{ url_for('guardar_tipos') }}", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({tipos: tipos, macs: macs})
  });
  if(resp.ok){
    alert("✅ Guardado correctamente");
    window.location.href = "{{ url_for('dashboard') }}";
  } else {
    alert("⚠️ Error guardando");
  }
}
</script>
</body>
</html>
"""

@app.route("/tipos", methods=["GET"])
def editar_tipos():
    tipos = cargar_tipos()
    macs = cargar_macs()
    emojis = ["📱","💻","📺","🍓","📶","🖨️","🔌","🧠","❓"]
    return render_template_string(EDITOR_HTML, tipos=tipos, macs=macs, emojis=emojis)

@app.route("/tipos/guardar", methods=["POST"])
def guardar_tipos():
    try:
        data = request.get_json(force=True)
        tipos_nuevos = data.get("tipos", [])
        macs_nuevos = data.get("macs", {})
        # Normalizar y validar
        cleaned_tipos = []
        for t in tipos_nuevos:
            kw = t.get("keywords", [])
            if isinstance(kw, list):
                kws = [str(x).strip() for x in kw if str(x).strip()]
            else:
                kws = [p.strip() for p in str(kw).split(",") if p.strip()]
            tipo = t.get("tipo","").strip()
            icono = t.get("icono","").strip() or "❓"
            color = t.get("color","").strip() or "#999999"
            if kws and tipo:
                cleaned_tipos.append({"keywords": kws, "tipo": tipo, "icono": icono, "color": color})
        ok1 = guardar_tipos(cleaned_tipos)
        cleaned_macs = {}
        for mac, info in macs_nuevos.items():
            m = str(mac).strip().lower()
            if not m:
                continue
            nombre = info.get("nombre", info.get("tipo","")).strip()
            tipo = info.get("tipo", nombre).strip()
            icono = info.get("icono","").strip() or "❓"
            color = info.get("color","#999999").strip()
            cleaned_macs[m] = {"nombre": nombre or tipo, "tipo": tipo or nombre, "icono": icono, "color": color}
        ok2 = guardar_macs(cleaned_macs)
        if ok1 and ok2:
            registrar_evento({"tipo":"tipos_macs_actualizados","detalle":{"tipos":len(cleaned_tipos),"macs":len(cleaned_macs)}})
            return ("ok",200)
    except Exception as e:
        print("Error guardar_tipos:", e)
    return ("error",500)

# Alias para JS (route más corta)
@app.route("/guardar_tipos", methods=["POST"])
def alias_guardar_tipos():
    return guardar_tipos()

# ---------------- Cambio de credenciales ----------------
@app.route("/cambiar_credenciales", methods=["GET", "POST"])
def cambiar_credenciales():
    # Al estar protegido por @app.before_request, request.authorization ya está presente y válida
    auth = request.authorization
    current_user = auth.username if auth else None

    if request.method == "POST":
        user_actual = request.form.get("user_actual", "").strip()
        pass_actual = request.form.get("pass_actual", "").strip()
        new_user = request.form.get("new_user", "").strip()
        new_pass = request.form.get("new_pass", "")
        confirm_pass = request.form.get("confirm_pass", "")

        # Validaciones básicas
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

        # Guardar nuevas credenciales de forma atómica y segura
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

        # Registrar evento y actualizar en memoria
        registrar_evento({
            "tipo": "credenciales_cambiadas",
            "detalle": {"by": user_actual, "timestamp": ahora_madrid_iso()}
        })
        global AUTH_USERNAME, AUTH_PASSWORD
        AUTH_USERNAME, AUTH_PASSWORD = new_user, new_pass

        # Preparar comando de reinicio
        if os.geteuid() == 0:
            cmd = ["systemctl", "restart", SERVICE_NAME]
        else:
            cmd = ["sudo", "systemctl", "restart", SERVICE_NAME]

        # Lanzar reinicio en hilo daemon para que ocurra mientras el navegador muestra la página de espera
        th = threading.Thread(target=_background_restart_service, args=(cmd,), daemon=True)
        th.start()

        # Mostrar página de espera y redirigir al dashboard tras 5 segundos
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
            // Precaución: además del meta-refresh, ponemos un fallback JS para redirigir
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

    # GET -> mostrar formulario
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

    estado_inicial = cargar_estado()
    dispositivos = [d for d in estado_inicial if d.get('online')]
    ultima_ips = set(d['ip'] for d in dispositivos if 'ip' in d)

    if not SCAPY_AVAILABLE:
        print("⚠️ Scapy no está disponible. Instala scapy: sudo pip3 install scapy")
    else:
        print("🛠 Scapy listo: usando ARP masivo para detección rápida.")

    print(f"🔎 Iniciando escaneo automático (INTERFACES={INTERFACES}). Estado cargado: {len(estado_inicial)} dispositivos (online: {len(dispositivos)}).")
    threading.Thread(target=hilo_seguro, daemon=True).start()
    # Nota: en producción usa un WSGI server (gunicorn, systemd) para mayor robustez.
    app.run(host="0.0.0.0", port=5000)