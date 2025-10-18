#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escaneo de red completo (Scapy, ARP, nmap opcional, ping) con persistencia,
dashboard web y editor de tipos/MACs.
"""

import time, threading, json, os, subprocess, ipaddress, tempfile, shutil, re, datetime
from pathlib import Path
from flask import Flask, render_template_string, request, Response
import pytz

# Scapy
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False

# ---------------- configuración ----------------
INTERVALO_ESCANEO = 30
INTERFACES = ["eth0","wlan0"]
TIEMPO_ESPERA_PING = 2

BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR/"estado_dispositivos.json"
EVENT_LOG_FILE = BASE_DIR/"eventos_red.log"
TIPOS_FILE = BASE_DIR/"tipos.json"
MACS_FILE = BASE_DIR/"macs.json"
CRED_FILE = BASE_DIR/"credservpas.xk"

SERVICE_NAME = "ServTableIP.service"

dispositivos = []
nuevos_detectados = []
desconectados = []
ultima_ips = set()
ultima_actualizacion = "Aún no se ha realizado un escaneo"
estado_lock = threading.Lock()
MADRID_TZ = pytz.timezone("Europe/Madrid")

# ---------------- Utilidades de tiempo ----------------
def convertir_a_horario_españa(timestamp_iso):
    if not timestamp_iso:
        return ""
    try:
        ts = timestamp_iso.replace("Z","+00:00") if timestamp_iso.endswith("Z") else timestamp_iso
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(MADRID_TZ).strftime("%d/%m/%Y %H:%M:%S")
    except:
        return timestamp_iso

def ahora_utc_iso_z():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

# ---------------- Persistencia ----------------
def _atomic_write(path,data_bytes):
    tmp_fd,tmp_path=tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd,"wb") as f:
            f.write(data_bytes)
        Path(tmp_path).replace(path)
    except:
        pass

def guardar_estado_atomic(estado_list):
    with estado_lock:
        _atomic_write(ESTADO_FILE,json.dumps(estado_list,ensure_ascii=False,indent=2).encode("utf-8"))

def cargar_estado():
    try:
        if ESTADO_FILE.exists():
            with ESTADO_FILE.open("r",encoding="utf-8") as f:
                data=json.load(f)
                return [dict(d,online=True) for d in data]
    except:
        pass
    return []

def registrar_evento(event):
    event.setdefault("timestamp", convertir_a_horario_españa(ahora_utc_iso_z()))
    event["timestamp_utc"]=ahora_utc_iso_z()
    with estado_lock:
        with EVENT_LOG_FILE.open("a",encoding="utf-8") as f:
            f.write(json.dumps(event,ensure_ascii=False)+"\n")

# ---------------- Tipos y MACs editables ----------------
def cargar_tipos():
    if TIPOS_FILE.exists():
        try:
            return json.load(TIPOS_FILE)
        except: pass
    return []

def cargar_macs():
    if MACS_FILE.exists():
        try:
            return json.load(MACS_FILE)
        except: pass
    return {}

def inferir_tipo(mac,vendor):
    # Primero MAC exacta
    macs = cargar_macs()
    if mac and mac.lower() in macs:
        t = macs[mac.lower()]
        return t["tipo"],t["icono"],t["color"],t.get("nombre","Desconocido")
    # Luego búsqueda por vendor
    tipos = cargar_tipos()
    v = (vendor or "").lower()
    for item in tipos:
        palabras=item["keywords"].lower().split(",")
        if any(p in v for p in palabras):
            return item["tipo"],item["icono"],item["color"],vendor
    # Default
    return "Desconocido","❓","#aaaaaa",vendor

# ---------------- Utilidades de red ----------------
def leer_tabla_arp():
    d={}
    try:
        salida=subprocess.check_output("ip neigh",shell=True).decode(errors="ignore")
        for l in salida.splitlines():
            partes=l.split()
            if "lladdr" in partes:
                d[partes[0]]=partes[parts.index("lladdr")+1]
    except:
        pass
    return d

def ping_host(ip,timeout=TIEMPO_ESPERA_PING):
    try:
        return subprocess.run(["ping","-c","1","-w",str(timeout),ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    except:
        return False

def obtener_ip_de_interfaz(iface):
    try:
        salida=subprocess.check_output(f"ip addr show {iface}",shell=True).decode(errors="ignore")
        m=re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)",salida)
        return m.group(1) if m else None
    except: return None

def obtener_mascara_de_interfaz(iface):
    try:
        salida=subprocess.check_output(f"ip addr show {iface}",shell=True).decode(errors="ignore")
        m=re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)",salida)
        return int(m.group(2)) if m else None
    except: return None

def obtener_mac_interfaz(iface):
    try:
        path=Path(f"/sys/class/net/{iface}/address")
        if path.exists():
            return path.read_text().strip().lower()
    except: pass
    return None

def interfaz_existe(iface):
    return Path(f"/sys/class/net/{iface}").exists()

# ---------------- Escaneo principal ----------------
def escanear_red():
    global dispositivos,nuevos_detectados,desconectados,ultima_ips,ultima_actualizacion
    tabla_arp=leer_tabla_arp()
    resultados={}
    now=ahora_utc_iso_z()
    for iface in INTERFACES:
        if not interfaz_existe(iface):
            continue
        ip=get_ip=obtener_ip_de_interfaz(iface)
        mask=obtener_mascara_de_interfaz(iface)
        if not ip or not mask: continue
        net=ipaddress.IPv4Network(f"{ip}/{mask}",strict=False)
        for h in net.hosts():
            ip=str(h)
            mac=tabla_arp.get(ip)
            vendor=None
            tipo,icono,color,fabricante=inferir_tipo(mac,vendor)
            resultados[ip]={"ip":ip,"mac":mac or "Desconocida","tipo":tipo,"icono":icono,"color":color,"fabricante":fabricante,
                            "first_seen":now,"last_seen":now,"seen_count":1}
    # Persistencia, nuevos y desconectados
    estado_prev=cargar_estado()
    mapa_prev={d['ip']:d for d in estado_prev}
    mapa_actual={}
    for ip,d in resultados.items():
        if ip in mapa_prev:
            d['first_seen']=mapa_prev[ip]['first_seen']
            d['seen_count']=mapa_prev[ip].get('seen_count',0)+1
        d['online']=True
        mapa_actual[ip]=d
    for ip,d in mapa_prev.items():
        if ip not in mapa_actual:
            offline=d.copy()
            offline['online']=False
            mapa_actual[ip]=offline
    actuales_ips={ip for ip,d in mapa_actual.items() if d.get('online')}
    prev_ips_online={ip for ip,d in mapa_prev.items() if d.get('online',True)}
    nuevos=actuales_ips-prev_ips_online
    descon=prev_ips_online-actuales_ips
    nuevos_detectados[:]=[mapa_actual[ip] for ip in nuevos]
    desconectados[:]=[mapa_actual[ip] for ip in mapa_actual if not mapa_actual[ip].get('online')]
    dispositivos[:] = sorted([d for d in mapa_actual.values() if d.get('online')], key=lambda d: ipaddress.IPv4Address(d['ip']))
    ultima_ips.clear()
    ultima_ips.update(actuales_ips)
    ultima_actualizacion=time.strftime("%Y-%m-%d %H:%M:%S")
    guardar_estado_atomic(sorted(mapa_actual.values(),key=lambda d: ipaddress.IPv4Address(d['ip'])))

# ---------------- Flask ----------------
app=Flask(__name__)
AUTH_USERNAME,AUTH_PASSWORD="admin","admin"

def _check_auth(u,p): return u==AUTH_USERNAME and p==AUTH_PASSWORD
def _authenticate(): return Response('Acceso requerido',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
@app.before_request
def proteger():
    auth=request.authorization
    if not auth or not _check_auth(auth.username,auth.password):
        return _authenticate()

PAGINA_TIPOS="""
<html><head><title>Editor Tipos/MACs</title></head><body>
<h2>Tipos de equipos</h2>
<form method="post">
<table border=1>
<tr><th>Keywords (coma separadas)</th><th>Tipo</th><th>Emoji</th><th>Color</th></tr>
{% for t in tipos %}
<tr>
<td><input name="keywords_{{loop.index}}" value="{{t.keywords}}"></td>
<td><input name="tipo_{{loop.index}}" value="{{t.tipo}}"></td>
<td><input name="icono_{{loop.index}}" value="{{t.icono}}"></td>
<td><input type="color" name="color_{{loop.index}}" value="{{t.color}}"></td>
</tr>
{% endfor %}
</table>
<button type="submit">Guardar tipos</button>
</form>
<h2>MACs exactas</h2>
<form method="post">
<table border=1>
<tr><th>MAC</th><th>Nombre</th><th>Tipo</th><th>Emoji</th><th>Color</th></tr>
{% for m,info in macs.items() %}
<tr>
<td><input name="mac_{{loop.index}}" value="{{m}}"></td>
<td><input name="nombre_{{loop.index}}" value="{{info.nombre}}"></td>
<td><input name="tipo_{{loop.index}}" value="{{info.tipo}}"></td>
<td><input name="icono_{{loop.index}}" value="{{info.icono}}"></td>
<td><input type="color" name="color_{{loop.index}}" value="{{info.color}}"></td>
</tr>
{% endfor %}
</table>
<button type="submit">Guardar MACs</button>
</form>
</body></html>
"""

@app.route("/tipos",methods=["GET","POST"])
def tipos():
    if request.method=="POST":
        tipos_list=[]
        macs_dict={}
        for k in request.form:
            v=request.form[k]
            if k.startswith("keywords_"):
                idx=k.split("_")[1]
                tipos_list.append({"keywords":v,"tipo":request.form.get(f"tipo_{idx}"),"icono":request.form.get(f"icono_{idx}"),"color":request.form.get(f"color_{idx}")})
            if k.startswith("mac_"):
                idx=k.split("_")[1]
                m=request.form.get(f"mac_{idx}").lower()
                macs_dict[m]={"nombre":request.form.get(f"nombre_{idx}"),"tipo":request.form.get(f"tipo_{idx}"),"icono":request.form.get(f"icono_{idx}"),"color":request.form.get(f"color_{idx}")}
        _atomic_write(TIPOS_FILE,json.dumps(tipos_list,ensure_ascii=False,indent=2).encode("utf-8"))
        _atomic_write(MACS_FILE,json.dumps(macs_dict,ensure_ascii=False,indent=2).encode("utf-8"))
        return "ok",200
    return render_template_string(PAGINA_TIPOS,tipos=cargar_tipos(),macs=cargar_macs())

@app.route("/")
def dashboard():
    tabla="".join(
        f"<tr style='background-color:{d.get('color','#fff')}'>"
        f"<td>{d.get('ip')}</td><td>{d.get('mac')}</td><td>{d.get('fabricante')}</td><td>{d.get('tipo')}</td><td>{d.get('icono')}</td><td>{convertir_a_horario_españa(d.get('first_seen'))}</td><td>{convertir_a_horario_españa(d.get('last_seen'))}</td><td>{d.get('seen_count')}</td></tr>"
        for d in dispositivos
    )
    alerta_nuevos="".join(f"<li>{d.get('ip')} - {d.get('tipo')} {d.get('icono')}</li>" for d in nuevos_detectados)
    return f"""
<html><head><title>Dashboard</title></head>
<body>
<h2>Dispositivos detectados</h2>
<a href="/tipos">🧩 Configurar tipos/MACs</a> | 
<a href="/cambiar_credenciales">🔑 Cambiar credenciales</a>
<table border=1>{tabla}</table>
<h3>Nuevos detectados</h3><ul>{alerta_nuevos}</ul>
</body></html>
"""

# ---------------- Main ----------------
if __name__=="__main__":
    BASE_DIR.mkdir(exist_ok=True)
    dispositivos=cargar_estado()
    threading.Thread(target=lambda:[escanear_red() or time.sleep(INTERVALO_ESCANEO) for _ in iter(int,1)],daemon=True).start()
    app.run(host="0.0.0.0",port=5000)