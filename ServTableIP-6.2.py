#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de red completo usando Scapy (ARP masivo) + nmap + arping + ping.
Persistencia de estado + historial de eventos (JSONL).
Ejecutar como root: sudo python3 scanner_scapy_persist.py
Soporta múltiples interfaces (ej: eth0 y/o wlan0).
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
from flask import Flask, render_template_string, request, Response
import json
import datetime
import tempfile
import os
import pytz

# scapy
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------------- configuración ----------------
INTERVALO_ESCANEO = 30
# ahora una lista: se comprobará cada interfaz en orden y se usará la que exista
INTERFACES = ["eth0", "wlan0"]
TIEMPO_ESPERA_PING = 2

# Rutas (ajusta si hace falta)
BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"    # persiste dispositivos conocidos (online + offline)
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"         # JSONL append-only (cada línea un evento)
OUI_FILE = BASE_DIR / "oui.txt"                        # fichero OUI local
CRED_FILE = BASE_DIR / "credservpas.xk"

# globales
dispositivos = []            # lista de dicts actuales ONLINE (se carga al iniciar, filtrada)
nuevos_detectados = []
desconectados = []           # lista de todos los conocidos OFFLINE (mostrados en la web)
ultima_ips = set()
ultima_actualizacion = "Aún no se ha realizado un escaneo"
_oui_dict = None

# lock para proteger accesos a archivo/estado
estado_lock = threading.Lock()

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

# ---------------- OUI helpers (reutilizadas) ----------------
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

def get_vendor(mac):
    key = normalize_mac(mac)
    if not key:
        return "Desconocido"
    oui = load_oui()
    return oui.get(key) or oui.get(key.replace(":", "")) or "Desconocido"

def infer_type_from_vendor(vendor, mac):
    v = (vendor or "").lower()
    if v == "desconocido" or not v:
        if mac:
            m = mac.lower()
            if m.startswith("b8:27:eb") or m.startswith("dc:a6:32"):
                return "Raspberry Pi", "🍓", "#f28b82", "Raspberry"
        return "Desconocido", "❓", "#aaaaaa", "Desconocido"
    if "apple" in v or "iphone" in v:
        return "iPhone/iPad/AppleTV", "📱/📺️", "#fbbc04", vendor
    if "amazon" in v or "amazon tecnologies inc." in v:
        return "FireStick", "📺️", "#fe8102", vendor
    if "samsung" in v or "samsung electronics" in v or "xiaomi" in v or "huawei" in v or "honor" in v or "oppo" in v or "oneplus" in v:
        return "Android", "🤖", "#34a853", vendor
    if "tct" in v or "tct mobile ltd" in v or "tp-link" in v or "sernet" in v:
        return "Router", "📶5G", "#dc143c", vendor
    if "hewlett" in v or "hp " in v or "dell" in v or "lenovo" in v or "asus" in v or "mitac" in v or "intel" in v:
        return "PC/Laptop", "💻", "#4285f4", vendor
    if "printer" in v or "epson" in v or "canon" in v or "hp " in v:
        return "Impresora", "🖨️", "#a142f4", vendor
    if "raspberry" in v:
        return "Raspberry Pi", "🍓", "#f28b82", vendor
    if "tuya smart inc." in v or "tuya" in v:
        return "Electrodomestico Cecotec", "⛂🧹", "#6a5acd", vendor
    if "espressif inc." in v or "espressif" in v:
        return "Enchufe ordenadores", "🔌", "#4285f4", vendor
    if "shenzhen bilian electronic co., ltd" in v or "shenzhen" in v:
        return "Tarjeta encendido PC remoto", "🔌", "#4285f4", vendor
    return "Desconocido", "❓", "#aaaaaa", vendor

# ---------------- utilidades de red (ahora parametrizadas por interfaz) ----------------
def obtener_ip_de_interfaz(iface):
    """Devuelve la IP (IPv4) asignada a la interfaz iface o None."""
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
    """Intenta leer la MAC del interfaz iface (devuelve en minúsculas)"""
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
        # establecer la interfaz en conf para que srp use la correcta
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

        # Detectar qué interfaces de la lista INTERFACES existen y tienen IP
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

        # leer tabla ARP global una vez por eficiencia
        tabla_arp_global = leer_tabla_arp()

        now_iso_utc = ahora_utc_iso_z()
        resultados_por_ip = {}  # ip -> dict con mayor info (mac,fabricante,tipo,...)

        # Por cada interfaz: scapy (si disponible), nmap (opcional) y fallback
        for iface, iface_ip, red in interfaces_disponibles:
            # 1) Scapy ARP por interfaz
            scapy_result = []
            if SCAPY_AVAILABLE:
                scapy_result = scapy_arp_scan_for_iface(red, iface, timeout=2, inter=0.0)
            mapa_scapy = {ip: mac for ip, mac in scapy_result}

            # 2) nmap
            mapa_nmap = {}
            for ip, mac, vendor in escanear_con_nmap(red):
                mapa_nmap[ip] = (mac, vendor)

            # 3) fusear por IPs de esta red
            for ip in (str(h) for h in red.hosts()):
                mac = None
                vendor = None
                source = None
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
                    # si ya hay una entrada por la misma IP, priorizar por fuente (scapy > nmap > arp_table)
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

        # 4) fallback: para IPs sin MACs en los redes detectadas, probar ping + arping por interfaz donde corresponda
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

        # convertir el mapa a lista
        lista_dispositivos = []
        for ip, d in resultados_por_ip.items():
            # limpiar campos internos y ajustar last_seen
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

        # ---------------- Merge con estado persistido anterior ----------------
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

        # ---------------- Asegurar inclusión de las IPs de las interfaces locales (cambio principal) ----------------
        for iface, iface_ip, red in interfaces_disponibles:
            try:
                local_ip = iface_ip
                local_mac = obtener_mac_interfaz(iface)
                if local_ip:
                    # Determinar fabricante/tipo por la MAC local si existe
                    vendor_local = get_vendor(local_mac) if local_mac else None
                    tipo_local, icono_local, color_local, fabricante_local = infer_type_from_vendor(vendor_local, local_mac)

                    # Usar nombre explícito para la máquina local indicando la interfaz
                    nombre_local = f"Equipo rastreador {iface}"

                    # Si no existe en mapa_actual, añadirlo con la etiqueta "Equipo rastreador <iface>"
                    if local_ip not in mapa_actual and local_mac:
                        mapa_actual[local_ip] = {
                            "ip": local_ip,
                            "mac": local_mac,
                            # host=Equipo rastreador <iface> (esto es lo que pediste)
                            "host": nombre_local,
                            # conservar fabricante detectado en "fabricante" para referencia
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
                        # Si ya existía, actualizamos algunos campos locales y forzamos el host
                        if local_mac and not mapa_actual[local_ip].get('mac'):
                            mapa_actual[local_ip]['mac'] = local_mac
                            mapa_actual[local_ip]['fabricante'] = fabricante_local
                        # Forzar que el host local sea "Equipo rastreador <iface>"
                        mapa_actual[local_ip]['host'] = nombre_local
                        # también forzar tipo/icono/color si quieres que destaque como local
                        mapa_actual[local_ip]['tipo'] = tipo_local
                        mapa_actual[local_ip]['icono'] = icono_local
                        mapa_actual[local_ip]['color'] = color_local
            except Exception:
                pass

        # Mantener en el estado anterior los hosts que no aparecen ahora (offline)
        for ip, prev in mapa_anterior.items():
            if ip not in mapa_actual:
                offline_entry = prev.copy()
                offline_entry['online'] = False
                mapa_actual[ip] = offline_entry

        # Detectar nuevos y desconectados comparando prev vs actual
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
    """Devuelve una respuesta 401 que provoca el prompt de autenticación en el navegador."""
    return Response(
        'Acceso requerido', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

@app.before_request
def proteger():  # se ejecuta antes de cada request
    # Si quieres añadir rutas públicas (health, metrics), puedes filtrarlas aquí:
    # if request.path in ("/health",): return None
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return _authenticate()

@app.route("/")
def dashboard():
    tabla = "".join(
        f"<tr style='background-color:{d.get('color','#ffffff')}'>"
        f"<td>{d.get('ip')}</td><td>{d.get('mac')}</td><td>{d.get('host')}</td>"
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
    alerta_desconectados = "".join(
        f"<li style='color:red; font-weight:bold'>{d.get('ip')} - {d.get('mac')} - {d.get('fabricante')} - {d.get('tipo')} ❌ Desconectado (última vez: {convertir_a_horario_españa(d.get('last_seen',''))})</li>"
        for d in desconectados
    )
    return render_template_string("""
    <html lang="es">
    <head>
        <meta http-equiv="refresh" content="10">
        <title>Escaneo de red (Scapy ARP + Persistencia)</title>
        <style>
            body { font-family: Arial; margin: 20px; background-color: #f8f9fa; }
            h2, h3 { color: #333; }
            table { border-collapse: collapse; width: 95%; background-color: white; }
            th, td { border: 1px solid #999; padding: 6px; text-align: center; font-size: 0.9em; }
            th { background-color: #e9ecef; }
            ul { list-style-type: none; padding-left: 0; }
            .timestamp { margin-top: 10px; font-size: 0.9em; color: #555; }
            .small { font-size: 0.8em; color: #666; }
        </style>
    </head>
    <body>
        <h2>📡 Dispositivos activos</h2>
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
        <p class="small">B174M3 // XaeK</p>
    </body>
    </html>
    """, tabla=tabla, alerta_nuevos=alerta_nuevos, alerta_desconectados=alerta_desconectados,
       ultima_actualizacion=ultima_actualizacion, scapy_ok=SCAPY_AVAILABLE,
       estado_file=str(ESTADO_FILE), log_file=str(EVENT_LOG_FILE))

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
    app.run(host="0.0.0.0", port=5000)
