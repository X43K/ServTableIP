#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de red completo usando Scapy (ARP masivo) + nmap + arping + ping.
Persistencia de estado + historial de eventos (JSONL).
Ejecutar como root: sudo python3 scanner_scapy_persist.py
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
from flask import Flask, render_template_string
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

from pathlib import Path

# ---------------- configuración ----------------
INTERVALO_ESCANEO = 30
INTERFAZ = "wlan0"
TIEMPO_ESPERA_PING = 2

# Rutas (ajusta si hace falta)
BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"    # persiste dispositivos conocidos (online + offline)
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"         # JSONL append-only (cada línea un evento)
OUI_FILE = BASE_DIR / "oui.txt"                        # fichero OUI local

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
    """
    Convierte un timestamp ISO (ej: 2025-10-10T08:34:21Z o con offset) a
    horario de España y devuelve string legible "DD/MM/YYYY HH:MM:SS".
    Si timestamp_iso está vacío o no parseable, devuelve cadena vacía o el original.
    """
    if not timestamp_iso:
        return ""
    try:
        # Reemplazar Z por +00:00 para que fromisoformat lo entienda
        ts = timestamp_iso
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        # fromisoformat maneja offsets como +00:00
        dt = datetime.datetime.fromisoformat(ts)
        # Si dt es naive (sin tzinfo), asumimos UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        # Convertir a Madrid
        dt_madrid = dt.astimezone(MADRID_TZ)
        return dt_madrid.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        # Si falla, devolver el original para diagnóstico
        return timestamp_iso

def ahora_utc_iso_z():
    """Devuelve ahora en UTC como ISO con Z (ej: 2025-10-10T08:34:21Z)."""
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def ahora_madrid_iso():
    """Devuelve ahora en horario Madrid como ISO con offset (ej: 2025-10-10T10:34:21+02:00)."""
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

# ---------------- utilidades de red ----------------
def obtener_ip_raspberry():
    try:
        salida_ip = subprocess.check_output(f"ip addr show {INTERFAZ}", shell=True).decode(errors="ignore")
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida_ip)
        return match.group(1) if match else None
    except Exception:
        return None

def obtener_mac_interfaz():
    """Intenta leer la MAC del interfaz INTERFAZ (devuelve en minúsculas)"""
    try:
        # 1) /sys/class/net (rápido y fiable en Linux)
        path = Path(f"/sys/class/net/{INTERFAZ}/address")
        if path.exists():
            mac = path.read_text().strip().lower()
            if mac:
                return mac
        # 2) fallback usando `ip link show INTERFAZ`
        salida = subprocess.check_output(f"ip link show {INTERFAZ}", shell=True).decode(errors="ignore")
        m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", salida)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return None

IP_RASPBERRY = obtener_ip_raspberry()

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

# ---------------- scapy ARP scan (rápido y fiable) ----------------
def scapy_arp_scan(red, timeout=2, inter=0.0):
    if not SCAPY_AVAILABLE:
        return []
    conf.verb = 0
    targets = [str(ip) for ip in red.hosts()]
    if not targets:
        return []
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=",".join(targets))
        ans, _ = srp(pkt, iface=INTERFAZ, timeout=timeout, inter=inter)
        resultados = []
        for snd, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.lower()
            resultados.append((ip, mac))
        return resultados
    except Exception as e:
        print("⚠️ scapy_arp_scan fallo:", e)
        return []

# ---------------- ping y arping helpers ----------------
def ping_host(ip, timeout=TIEMPO_ESPERA_PING):
    try:
        res = subprocess.run(["ping", "-c", "1", "-w", str(timeout), ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def arping_forzar(ip):
    arping_bin = shutil.which("arping")
    if not arping_bin:
        return False
    try:
        subprocess.run([arping_bin, "-c", "1", "-I", INTERFAZ, ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False

# ---------------- Persistencia / logging ----------------
def _atomic_write(path: Path, data: bytes):
    """Escribe de forma atómica al disco (usa archivo temporal y renombra)."""
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
    """Guarda dispositivos (lista de dicts) en ESTADO_FILE de forma atómica."""
    try:
        with estado_lock:
            data = json.dumps(estado_list, ensure_ascii=False, indent=2).encode("utf-8")
            _atomic_write(ESTADO_FILE, data)
    except Exception as e:
        print("⚠️ Error al guardar estado:", e)

def cargar_estado():
    """Carga estado desde ESTADO_FILE (devuelve lista de dicts)."""
    try:
        if ESTADO_FILE.exists():
            with ESTADO_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    # compat: si registros previos no tienen 'online', asumimos True
                    for d in data:
                        if 'online' not in d:
                            d['online'] = True
                    return data
    except Exception as e:
        print("⚠️ Error al cargar estado:", e)
    return []

def registrar_evento(event):
    """
    Añade un evento en formato JSONL a EVENT_LOG_FILE.
    event: dict (se añadirá timestamp si no existe).
    Ahora el 'timestamp' en el log será en horario de España (ISO con offset).
    También se añade 'timestamp_utc' con el valor UTC (terminado en Z).
    """
    try:
        if 'timestamp' not in event:
            event['timestamp'] = ahora_madrid_iso()  # ISO con offset de Madrid
        # también dejar referencia UTC
        event['timestamp_utc'] = ahora_utc_iso_z()
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with estado_lock:
            with EVENT_LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        print("⚠️ Error al registrar evento:", e)

# ---------------- Escaneo principal (con persistencia) ----------------
def escanear_red():
    global dispositivos, nuevos_detectados, desconectados, ultima_ips, ultima_actualizacion
    try:
        lista_dispositivos = []

        # obtener ip y máscara local
        try:
            salida_ip = subprocess.check_output(f"ip addr show {INTERFAZ}", shell=True).decode(errors="ignore")
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida_ip)
            if not match:
                print("⚠️ No se pudo obtener IP/máscara de interfaz", INTERFAZ)
                return
            ip_base = match.group(1)
            mascara = int(match.group(2))
            red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)
        except Exception as e:
            print("⚠️ Falló lectura IP/mascara:", e)
            return

        # 1) Scapy ARP masivo
        scapy_result = []
        if SCAPY_AVAILABLE:
            scapy_result = scapy_arp_scan(red, timeout=2, inter=0.0)
        mapa_scapy = {ip: mac for ip, mac in scapy_result}

        # 2) nmap rápido para complementar
        mapa_nmap = {}
        for ip, mac, vendor in escanear_con_nmap(red):
            mapa_nmap[ip] = (mac, vendor)

        # 3) leer tabla ARP
        tabla_arp = leer_tabla_arp()

        # 4) construir lista combinando fuentes (prioridad: scapy > nmap > arp_table)
        now_iso_utc = ahora_utc_iso_z()
        for ip in (str(h) for h in red.hosts()):
            mac = None
            vendor = None
            if ip in mapa_scapy:
                mac = mapa_scapy[ip]
                vendor = get_vendor(mac)
            elif ip in mapa_nmap:
                mac, vendor = mapa_nmap[ip]
                if mac:
                    mac = mac.lower()
                else:
                    mac = tabla_arp.get(ip)
                    vendor = vendor or get_vendor(mac)
            else:
                mac = tabla_arp.get(ip)
                if mac:
                    vendor = get_vendor(mac)

            if mac:
                tipo, icono, color, fabricante = infer_type_from_vendor(vendor, mac)
                host = fabricante
                lista_dispositivos.append({
                    "ip": ip,
                    "mac": mac if mac else "Desconocida",
                    "host": host,
                    "tipo": tipo,
                    "icono": icono,
                    "color": color,
                    "fabricante": fabricante,
                    # metadatos para persistencia (guardamos en UTC para consistencia)
                    "first_seen": now_iso_utc,
                    "last_seen": now_iso_utc,
                    "seen_count": 1
                })

        # 5) fallback: para IPs que aún no encontraron MACs, probar ping + arping concurrente
        actuales_ips = set(d['ip'] for d in lista_dispositivos)
        ips_pendientes = [str(h) for h in red.hosts() if str(h) not in actuales_ips]
        arping_available = shutil.which("arping") is not None

        def probar_ip(ip):
            if ping_host(ip, timeout=TIEMPO_ESPERA_PING):
                if arping_available:
                    arping_forzar(ip)
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
                        "first_seen": now_iso_utc,
                        "last_seen": now_iso_utc,
                        "seen_count": 1
                    }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
            futuros = [ex.submit(probar_ip, ip) for ip in ips_pendientes]
            for fut in concurrent.futures.as_completed(futuros, timeout=300):
                try:
                    res = fut.result()
                    if res:
                        lista_dispositivos.append(res)
                except Exception:
                    pass

        # ---------------- Merge con estado persistido anterior ----------------
        # cargar estado anterior (ahora puede contener también offline)
        estado_anterior = cargar_estado()
        mapa_anterior = {d['ip']: d for d in estado_anterior if 'ip' in d}

        # actualizamos metadatos: si ya venía en estado anterior, preservamos first_seen y aumentamos counters
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
            # actualizar last_seen (almacenamos en UTC)
            d['last_seen'] = ahora_utc_iso_z()
            # --- CAMBIO: marcar online True para los detectados ahora
            d['online'] = True
            mapa_actual[ip] = d

        # ---------------- Asegurar inclusión del propio equipo ----------------
        try:
            local_ip = ip_base if 'ip_base' in locals() else obtener_ip_raspberry()
            local_mac = obtener_mac_interfaz()
            if local_ip:
                if local_ip not in mapa_actual and local_mac:
                    vendor = get_vendor(local_mac)
                    tipo, icono, color, fabricante = infer_type_from_vendor(vendor, local_mac)
                    mapa_actual[local_ip] = {
                        "ip": local_ip,
                        "mac": local_mac,
                        "host": fabricante,
                        "tipo": tipo,
                        "icono": icono,
                        "color": color,
                        "fabricante": fabricante,
                        "first_seen": now_iso_utc,
                        "last_seen": ahora_utc_iso_z(),
                        "seen_count": 1,
                        "online": True
                    }
                elif local_ip in mapa_actual:
                    if not mapa_actual[local_ip].get('mac') and local_mac:
                        mapa_actual[local_ip]['mac'] = local_mac
                        mapa_actual[local_ip]['fabricante'] = get_vendor(local_mac)
        except Exception:
            pass

        # ---------------- Mantener en el estado anterior los hosts que no aparecen ahora (offline)
        for ip, prev in mapa_anterior.items():
            if ip not in mapa_actual:
                # conservar el registro previo, marcar offline (no actualizar first_seen ni last_seen)
                offline_entry = prev.copy()
                offline_entry['online'] = False
                mapa_actual[ip] = offline_entry

        # ---------------- Detectar nuevos y desconectados comparando prev vs actual (por estado anterior)
        actuales_ips = {ip for ip, d in mapa_actual.items() if d.get('online')}
        prev_ips_online = {ip for ip, d in mapa_anterior.items() if d.get('online', True)}
        # nuevos = los que están ahora online y antes no estaban online
        nuevos = actuales_ips - prev_ips_online
        # descon = los que antes estaban online y ahora no (o no están online)
        descon = prev_ips_online - actuales_ips

        nuevos_detectados[:] = [mapa_actual[ip] for ip in nuevos]
        # desconectados como lista de registros offline (persistidos). Esto cumple tu requisito:
        desconectados[:] = [mapa_actual[ip] for ip in mapa_actual if not mapa_actual[ip].get('online')]

        # registrar eventos
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
        # además registrar "visto" para hosts que ya estaban online y siguen online
        for ip in (actuales_ips & prev_ips_online):
            d = mapa_actual[ip]
            registrar_evento({
                "ip": ip,
                "mac": d.get('mac'),
                "tipo": "visto",
                "detalle": {"last_seen": d.get('last_seen')}
            })

        # reconstruir lista_dispositivos finales: sólo los online para la tabla principal
        dispositivos_final = sorted([d for d in mapa_actual.values() if d.get('online')], key=lambda d: ipaddress.IPv4Address(d['ip']))
        dispositivos[:] = dispositivos_final

        # actualizamos ultima_ips (con los online actuales)
        ultima_ips.clear()
        ultima_ips.update(actuales_ips)
        ultima_actualizacion = time.strftime("%Y-%m-%d %H:%M:%S")

        # guardar estado de forma atómica: guardamos TODOS los dispositivos (online + offline)
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
@app.route("/")
def dashboard():
    # tabla de activos (dispositivos tiene sólo los online)
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
    # ahora desconectados contiene TODOS los conocidos offline
    alerta_desconectados = "".join(
        f"<li style='color:red; font-weight:bold'>{d.get('ip')} - {d.get('mac')} - {d.get('fabricante')} - {d.get('tipo')} ❌ Desconectado (última vez: {convertir_a_horario_españa(d.get('last_seen',''))})</li>"
        for d in desconectados
    )
    return render_template_string("""
    <html>
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
    </body>
    </html>
    """, tabla=tabla, alerta_nuevos=alerta_nuevos, alerta_desconectados=alerta_desconectados,
       ultima_actualizacion=ultima_actualizacion, scapy_ok=SCAPY_AVAILABLE,
       estado_file=str(ESTADO_FILE), log_file=str(EVENT_LOG_FILE))

# ---------------- main ----------------
if __name__ == "__main__":
    # asegurar directorio base exista
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # cargar estado inicial (persistido) si existe
    estado_inicial = cargar_estado()
    # dispositivos (en memoria para la tabla) serán solo los ONLINE
    dispositivos = [d for d in estado_inicial if d.get('online')]
    ultima_ips = set(d['ip'] for d in dispositivos if 'ip' in d)

    if not SCAPY_AVAILABLE:
        print("⚠️ Scapy no está disponible. Instala scapy: sudo pip3 install scapy")
    else:
        print("🛠 Scapy listo: usando ARP masivo para detección rápida.")
    print(f"🔎 Iniciando escaneo automático (INTERFAZ={INTERFAZ}). Estado cargado: {len(estado_inicial)} dispositivos (online: {len(dispositivos)}).")
    threading.Thread(target=hilo_seguro, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
