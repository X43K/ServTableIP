#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escaneo de red completo con Scapy, nmap, ping y arping.
Persistencia en JSON, logs y UI web con Flask.
Incluye gestión de tipos de dispositivos y MACs conocidas.
"""

import time, threading, socket, re, ipaddress, shutil, subprocess, concurrent.futures
from pathlib import Path
import json, datetime, tempfile, os, pytz, sys
from flask import Flask, render_template_string, request, Response, redirect, url_for

# ---------------- Scapy ----------------
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------------- Configuración ----------------
INTERVALO_ESCANEO = 30
INTERFACES = ["eth0", "wlan0"]
TIEMPO_ESPERA_PING = 2

BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"
TIPOS_FILE = BASE_DIR / "tipos_dispositivos.json"
MACS_FILE = BASE_DIR / "macs_conocidas.json"
CRED_FILE = BASE_DIR / "credservpas.xk"
SERVICE_NAME = "ServTableIP.service"
IP_PRIORITARIA = "***.***.***.**1"

dispositivos = []
nuevos_detectados = []
desconectados = []
ultima_ips = set()
ultima_actualizacion = "Aún no se ha realizado un escaneo"

estado_lock = threading.Lock()
MADRID_TZ = pytz.timezone("Europe/Madrid")

# ---------------- Utilidades tiempo ----------------
def convertir_a_horario_españa(timestamp_iso):
    if not timestamp_iso: return ""
    try:
        ts = timestamp_iso
        if ts.endswith("Z"): ts = ts.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=datetime.timezone.utc)
        dt_madrid = dt.astimezone(MADRID_TZ)
        return dt_madrid.strftime("%d/%m/%Y %H:%M:%S")
    except: return timestamp_iso

def ahora_utc_iso_z(): return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def ahora_madrid_iso():
    dt_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    dt_madrid = dt_utc.astimezone(MADRID_TZ)
    return dt_madrid.replace(microsecond=0).isoformat()

# ---------------- OUI / MAC ----------------
_oui_dict = None
def load_oui():
    global _oui_dict
    if _oui_dict is not None: return _oui_dict
    d = {}
    oui_file = BASE_DIR / "oui.txt"
    if oui_file.exists():
        try:
            for line in oui_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "(hex)" in line:
                    parts = line.split()
                    prefix = parts[0].replace("-", ":").lower()
                    vendor = " ".join(parts[2:]).strip()
                    d[prefix] = vendor
        except: pass
    _oui_dict = d
    return _oui_dict

def normalize_mac(mac):
    if not mac: return None
    m = mac.strip().lower().replace("-", ":")
    if m in ("<incomplete>", "desconocida", "unknown"): return None
    octs = m.split(":")
    if len(octs) < 3: return None
    return ":".join(octs[:3])

def canonical_mac(mac):
    if not mac: return None
    m = mac.strip().lower().replace("-", ":").replace(".", ":")
    m_n = re.sub(r'[^0-9a-f:]', '', m)
    if ":" not in m_n and len(m_n) == 12:
        m_n = ":".join([m_n[i:i+2] for i in range(0,12,2)])
    return m_n

def get_vendor(mac):
    key = normalize_mac(mac)
    if not key: return "Desconocido"
    oui = load_oui()
    return oui.get(key) or oui.get(key.replace(":","")) or "Desconocido"

# ---------------- Tipos / MACs persistentes ----------------
def cargar_json(path, default):
    if path.exists():
        try:
            data = json.load(path.open("r", encoding="utf-8"))
            return data
        except: pass
    return default

def guardar_json(path, data):
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
    with os.fdopen(tmp_fd,"w", encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False, indent=2)
    os.replace(tmp_path, str(path))

TIPOS_DISPOSITIVOS = cargar_json(TIPOS_FILE, {
    "apple": ["iPhone/iPad/AppleTV", "📱/📺️", "#fbbc04"],
    "hewlett,hp,dell,lenovo,asus,mitac,intel": ["PC/Laptop","💻","#4285f4"],
    "raspberry": ["Raspberry Pi","🍓","#f28b82"],
    "amazon": ["FireStick","📺️","#fe8102"],
    "samsung,xiaomi,huawei,honor,oppo,oneplus": ["Android","🤖","#34a853"]
})
MACS_CONOCIDAS = cargar_json(MACS_FILE, {})

def infer_type_from_vendor(vendor, mac):
    v = (vendor or "").lower()
    # buscar por MAC exacta primero
    if mac in MACS_CONOCIDAS: 
        nombre, tipo, icono, color = MACS_CONOCIDAS[mac]
        return tipo, icono, color, nombre
    for keys, val in TIPOS_DISPOSITIVOS.items():
        if any(k in v for k in keys.split(",")):
            return val[0], val[1], val[2], vendor
    return "Desconocido","❓","#aaaaaa",vendor

# ---------------- Red ----------------
def obtener_ip_de_interfaz(iface):
    try:
        salida = subprocess.check_output(f"ip addr show {iface}", shell=True).decode(errors="ignore")
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida)
        return m.group(1) if m else None
    except: return None

def obtener_mascara_de_interfaz(iface):
    try:
        salida = subprocess.check_output(f"ip addr show {iface}", shell=True).decode(errors="ignore")
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida)
        return int(m.group(2)) if m else None
    except: return None

def obtener_mac_interfaz(iface):
    try:
        p = Path(f"/sys/class/net/{iface}/address")
        if p.exists(): return p.read_text().strip().lower()
        salida = subprocess.check_output(f"ip link show {iface}", shell=True).decode(errors="ignore")
        m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", salida)
        if m: return m.group(1).lower()
    except: return None

def interfaz_existe(iface): return Path(f"/sys/class/net/{iface}").exists()

def leer_tabla_arp():
    d = {}
    try:
        salida = subprocess.check_output("ip neigh", shell=True).decode(errors="ignore")
        for l in salida.splitlines():
            partes = l.split()
            if len(partes) >=5 and "lladdr" in partes:
                d[partes[0]] = partes[partes.index("lladdr")+1]
    except:
        try:
            salida = subprocess.check_output("arp -n", shell=True).decode(errors="ignore")
            for linea in salida.splitlines()[1:]:
                partes = re.split(r'\s+', linea)
                if len(partes)>=3: d[partes[0]]=partes[2]
        except: pass
    return d

def ping_host(ip, timeout=TIEMPO_ESPERA_PING):
    try: return subprocess.run(["ping","-c","1","-w",str(timeout),ip], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    except: return False

def arping_forzar(ip, iface):
    arping_bin = shutil.which("arping")
    if not arping_bin: return False
    try: subprocess.run([arping_bin,"-c","1","-I",iface,ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    except: return False
    return True

# ---------------- Logging ----------------
def registrar_evento(event):
    if 'timestamp' not in event: event['timestamp'] = ahora_madrid_iso()
    event['timestamp_utc'] = ahora_utc_iso_z()
    line = json.dumps(event, ensure_ascii=False)+"\n"
    with estado_lock:
        with EVENT_LOG_FILE.open("a", encoding="utf-8") as f: f.write(line)

# ---------------- Escaneo principal ----------------
def escanear_red():
    global dispositivos, nuevos_detectados, desconectados, ultima_ips, ultima_actualizacion
    try:
        interfaces_disponibles = []
        for iface in INTERFACES:
            if interfaz_existe(iface):
                ip = obtener_ip_de_interfaz(iface)
                mask = obtener_mascara_de_interfaz(iface)
                if ip and mask:
                    try: red = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    except: continue
                    interfaces_disponibles.append((iface, ip, red))
        if not interfaces_disponibles: return

        tabla_arp_global = leer_tabla_arp()
        now_iso_utc = ahora_utc_iso_z()
        resultados_por_ip = {}

        for iface, iface_ip, red in interfaces_disponibles:
            # Scapy
            scapy_result = []
            if SCAPY_AVAILABLE:
                try:
                    conf.iface = iface
                    conf.verb=0
                    targets = [str(ip) for ip in red.hosts()]
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=",".join(targets))
                    ans,_ = srp(pkt, iface=iface, timeout=2, inter=0.0)
                    scapy_result = [(rcv.psrc, rcv.hwsrc.lower()) for snd, rcv in ans]
                except: pass
            mapa_scapy = {ip:mac for ip,mac in scapy_result}

            # IP prioritaria
            if IP_PRIORITARIA in mapa_scapy:
                mac = mapa_scapy[IP_PRIORITARIA]
                tipo, icono, color, fabricante = infer_type_from_vendor(get_vendor(mac), mac)
                resultados_por_ip[IP_PRIORITARIA] = {
                    "ip": IP_PRIORITARIA,"mac":mac,"host":fabricante,
                    "tipo":tipo,"icono":icono,"color":color,"fabricante":fabricante,
                    "first_seen": now_iso_utc,"last_seen": now_iso_utc,
                    "seen_count":1,"_src":"scapy@"+iface,"_iface":iface
                }

            # resto de hosts
            for h in red.hosts():
                ip = str(h)
                if ip == IP_PRIORITARIA: continue
                mac = mapa_scapy.get(ip) or tabla_arp_global.get(ip)
                if not mac: continue
                tipo, icono, color, fabricante = infer_type_from_vendor(get_vendor(mac), mac)
                resultados_por_ip[ip] = {
                    "ip": ip,"mac": mac,"host": fabricante,
                    "tipo": tipo,"icono": icono,"color": color,"fabricante": fabricante,
                    "first_seen": now_iso_utc,"last_seen": now_iso_utc,
                    "seen_count": 1,"_src":"scapy@"+iface,"_iface":iface
                }

        # Construir lista final
        lista_dispositivos = [d for d in resultados_por_ip.values()]
        dispositivos[:] = sorted(lista_dispositivos, key=lambda d: ipaddress.IPv4Address(d['ip']))
        ultima_ips.clear()
        ultima_ips.update(resultados_por_ip.keys())
        ultima_actualizacion = time.strftime("%Y-%m-%d %H:%M:%S")
        guardar_json(ESTADO_FILE, dispositivos)
    except Exception as e:
        print("⚠️ Error en escaneo:", e)

def hilo_seguro():
    while True:
        try: escanear_red()
        except Exception as e: print("⚠️ Error en hilo de escaneo:", e)
        time.sleep(INTERVALO_ESCANEO)

# ---------------- Flask ----------------
app = Flask(__name__)

# ---------------- Credenciales ----------------
def cargar_credenciales():
    try:
        if CRED_FILE.exists():
            lineas = [l.strip() for l in CRED_FILE.read_text("utf-8").splitlines() if l.strip()]
            if len(lineas)>=2: return lineas[0], lineas[1]
    except: pass
    return None,None
AUTH_USERNAME, AUTH_PASSWORD = cargar_credenciales()
if not AUTH_USERNAME or not AUTH_PASSWORD: AUTH_USERNAME=AUTH_PASSWORD="admin"

def _check_auth(u,p): return u==AUTH_USERNAME and p==AUTH_PASSWORD
def _authenticate(): return Response('Acceso requerido',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
@app.before_request
def proteger():
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password): return _authenticate()

# ---------------- UI Principal ----------------
@app.route("/")
def dashboard():
    tabla = "".join(f"<tr style='background-color:{d.get('color','#fff')}'>"
        f"<td>{d.get('ip')}</td><td>{d.get('mac')}</td><td>{d.get('host')}</td>"
        f"<td>{d.get('fabricante')}</td><td>{d.get('tipo')}</td><td>{d.get('icono')}</td>"
        f"<td>{convertir_a_horario_españa(d.get('first_seen',''))}</td>"
        f"<td>{convertir_a_horario_españa(d.get('last_seen',''))}</td>"
        f"<td>{d.get('seen_count',0)}</td></tr>" for d in dispositivos)
    return render_template_string("""
    <html lang="es">
    <head>
        <meta http-equiv="refresh" content="10">
        <title>Escaneo de red</title>
    </head>
    <body>
        <h1>📡 Dispositivos activos</h1>
        <a href="{{ url_for('cambiar_credenciales') }}">🔑 Cambiar credenciales</a>
        <a href="{{ url_for('configuracion_tipos') }}">⚙️ Configuración de dispositivos</a>
        <table border="1"><tr>
        <th>IP</th><th>MAC</th><th>Host</th><th>Fabricante</th><th>Tipo</th><th>Icono</th><th>Primera vez</th><th>Última vez</th><th>Veces visto</th></tr>
        {{ tabla|safe }}</table>
        <p>Último escaneo: {{ ultima_actualizacion }}</p>
    </body>
    </html>
    """, tabla=tabla, ultima_actualizacion=ultima_actualizacion)

# ---------------- UI Configuración ----------------
@app.route("/configuracion", methods=["GET","POST"])
def configuracion_tipos():
    global TIPOS_DISPOSITIVOS, MACS_CONOCIDAS
    if request.method=="POST":
        # Guardar cambios tipos
        for k in request.form:
            if k.startswith("tipo_"):
                key = k[5:]
                val = request.form[k].split("|")
                if len(val)==3: TIPOS_DISPOSITIVOS[key] = val
        # Guardar cambios MACs
        for k in request.form:
            if k.startswith("mac_"):
                mac = k[4:]
                val = request.form[k].split("|")
                if len(val)==4: MACS_CONOCIDAS[mac] = val
        guardar_json(TIPOS_FILE, TIPOS_DISPOSITIVOS)
        guardar_json(MACS_FILE, MACS_CONOCIDAS)
        return redirect(url_for('configuracion_tipos'))

    # Formulario HTML
    tipos_html = "".join(f"<tr><td>{k}</td><td><input name='tipo_{k}' value='{','.join(v)}'></td></tr>"
                         for k,v in TIPOS_DISPOSITIVOS.items())
    macs_html = "".join(f"<tr><td>{m}</td><td>{','.join(v)}</td></tr>" for m,v in MACS_CONOCIDAS.items())
    return render_template_string("""
    <h2>Configuración de Tipos y MACs</h2>
    <form method="post">
    <h3>Tipos de dispositivos</h3>
    <table border="1"><tr><th>Keys</th><th>Tipo,Icono,Color</th></tr>{{ tipos_html|safe }}</table>
    <h3>MACs conocidas</h3>
    <table border="1"><tr><th>MAC</th><th>Nombre,Tipo,Icono,Color</th></tr>{{ macs_html|safe }}</table>
    <button type="submit">Guardar cambios</button>
    </form>
    """, tipos_html=tipos_html, macs_html=macs_html)

# ---------------- Main ----------------
if __name__=="__main__":
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=hilo_seguro, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)