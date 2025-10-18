#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitor de red completo con Scapy ARP + dashboard web.
- Escaneo de red ARP masivo
- Identificación de tipo mediante tabla editable y MACs específicas
- Persistencia y registro de eventos
- Dashboard Flask con editor de tipos y MACs especiales
"""

import time, threading, re, json, datetime, subprocess, tempfile, os, shutil
from pathlib import Path
from flask import Flask, render_template_string, request, Response
import pytz
import ipaddress

# ---------------- Config ----------------
BASE_DIR = Path(__file__).resolve().parent
ESTADO_FILE = BASE_DIR / "estado_dispositivos.json"
EVENT_LOG_FILE = BASE_DIR / "eventos_red.log"
TIPOS_FILE = BASE_DIR / "tipos.json"
MACS_FILE = BASE_DIR / "macs.json"
CRED_FILE = BASE_DIR / "credservpas.xk"
INTERFACES = ["eth0","wlan0"]
TIEMPO_PING = 2
MADRID_TZ = pytz.timezone("Europe/Madrid")

# ---------------- Globals ----------------
dispositivos = []
nuevos_detectados = []
ultima_ips = set()
estado_lock = threading.Lock()
SCAPY_AVAILABLE = False

# ---------------- Scapy ----------------
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except: pass

# ---------------- Utilidades ----------------
def ahora_madrid():
    dt = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(MADRID_TZ).strftime("%d/%m/%Y %H:%M:%S")

def _atomic_write(path: Path, data: bytes):
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd,"wb") as f:
            f.write(data)
        Path(tmp_path).replace(path)
    finally:
        if Path(tmp_path).exists(): Path(tmp_path).unlink(missing_ok=True)

# ---------------- Persistencia ----------------
def guardar_estado():
    with estado_lock:
        _atomic_write(ESTADO_FILE, json.dumps(dispositivos, ensure_ascii=False, indent=2).encode("utf-8"))

def cargar_estado():
    if ESTADO_FILE.exists():
        try: return json.load(ESTADO_FILE.open("r", encoding="utf-8"))
        except: return []
    return []

def registrar_evento(event):
    event['timestamp'] = ahora_madrid()
    with estado_lock:
        with EVENT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False)+"\n")

# ---------------- Tipos dinámicos ----------------
def cargar_tipos():
    if TIPOS_FILE.exists():
        try: return json.load(TIPOS_FILE.open("r", encoding="utf-8"))
        except: pass
    return [
        {"keywords":["apple","iphone"],"tipo":"iPhone/iPad/AppleTV","icono":"📱","color":"#fbbc04"},
        {"keywords":["hewlett","hp","dell","lenovo","asus","mitac","intel"],"tipo":"PC/Laptop","icono":"💻","color":"#4285f4"},
        {"keywords":["raspberry"],"tipo":"Raspberry Pi","icono":"🍓","color":"#f28b82"},
        {"keywords":["tct","tp-link"],"tipo":"Router","icono":"📶","color":"#dc143c"},
    ]

def cargar_macs():
    if MACS_FILE.exists():
        try: return json.load(MACS_FILE.open("r", encoding="utf-8"))
        except: pass
    return {}  # mac -> {"nombre":..., "tipo":..., "icono":..., "color":...}

def infer_type(vendor, mac):
    mac_lower = (mac or "").lower()
    macs = cargar_macs()
    if mac_lower in macs:
        entry = macs[mac_lower]
        return entry.get("nombre",entry.get("tipo","Desconocido")), entry.get("icono","❓"), entry.get("color","#aaaaaa")
    v = (vendor or "").lower()
    tipos = cargar_tipos()
    for t in tipos:
        if any(k.lower() in v for k in t.get("keywords",[])):
            return t["tipo"], t.get("icono","❓"), t.get("color","#aaaaaa")
    if mac_lower.startswith(("b8:27:eb","dc:a6:32")):
        return "Raspberry Pi","🍓","#f28b82"
    return "Desconocido","❓","#aaaaaa"

# ---------------- Escaneo ----------------
def obtener_tabla_arp():
    d = {}
    try:
        salida = subprocess.check_output("ip neigh", shell=True).decode()
        for l in salida.splitlines():
            p=l.split()
            if len(p)>=5 and "lladdr" in p:
                idx = p.index("lladdr")
                d[p[0]] = p[idx+1]
    except: pass
    return d

def scapy_arp_scan(red):
    resultados = []
    if not SCAPY_AVAILABLE: return resultados
    conf.verb=0
    targets = [str(ip) for ip in red.hosts()]
    if not targets: return resultados
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=",".join(targets))
    try:
        ans,_ = srp(pkt, timeout=2, inter=0.0)
        for _,rcv in ans:
            resultados.append((rcv.psrc, rcv.hwsrc.lower()))
    except: pass
    return resultados

def escanear_red():
    global dispositivos, nuevos_detectados, ultima_ips
    nuevos_detectados=[]
    resultados_por_ip={}
    tabla_arp = obtener_tabla_arp()
    interfaces_validas=[]
    for iface in INTERFACES:
        try:
            salida = subprocess.check_output(f"ip addr show {iface}", shell=True).decode()
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", salida)
            if m:
                ip_base, mask = m.group(1), int(m.group(2))
                red = ipaddress.IPv4Network(f"{ip_base}/{mask}", strict=False)
                interfaces_validas.append((iface,red))
        except: continue

    now_iso = ahora_madrid()
    for iface, red in interfaces_validas:
        scan_res = scapy_arp_scan(red)
        for ip, mac in scan_res:
            vendor = "Desconocido"
            tipo, icono, color = infer_type(vendor, mac)
            resultados_por_ip[ip] = {"ip":ip,"mac":mac,"tipo":tipo,"icono":icono,"color":color,"last_seen":now_iso}

    dispositivos=[]
    for ip, info in resultados_por_ip.items():
        dispositivos.append(info)
        if ip not in ultima_ips:
            nuevos_detectados.append({"ip":ip,"tipo":info["tipo"],"icono":info["icono"]})
    ultima_ips=set(resultados_por_ip.keys())
    guardar_estado()

# ---------------- Flask ----------------
app = Flask(__name__)

# ---------------- Credenciales ----------------
def cargar_credenciales():
    if CRED_FILE.exists():
        lines=[l.strip() for l in CRED_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
        if len(lines)>=2: return lines[0],lines[1]
    return "admin","admin"

AUTH_USERNAME, AUTH_PASSWORD = cargar_credenciales()
def _check_auth(u,p): return u==AUTH_USERNAME and p==AUTH_PASSWORD
def _authenticate(): return Response('Acceso requerido', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})
@app.before_request
def proteger():
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return _authenticate()

# ---------------- Web UI ----------------
PAGINA_TIPOS = """
<html><head><title>Configurar tipos</title></head>
<body>
<h2>Tipos de dispositivos</h2>
<table border=1>
<tr><th>Keywords (coma separados)</th><th>Tipo</th><th>Emoji</th><th>Color</th></tr>
{% for t in tipos %}
<tr>
<td><input value="{{ ','.join(t.keywords) }}" class="keywords"/></td>
<td><input value="{{ t.tipo }}" class="tipo"/></td>
<td>
<select class="emoji">
<option>📱</option><option>💻</option><option>🍓</option><option>📶</option><option>❓</option>
</select>
</td>
<td><input type="color" value="{{ t.color }}" class="color"/></td>
</tr>
{% endfor %}
</table>
<h2>MACs específicas</h2>
<table border=1>
<tr><th>MAC</th><th>Nombre/Tipo</th><th>Emoji</th><th>Color</th></tr>
{% for mac,info in macs.items() %}
<tr>
<td><input value="{{ mac }}" class="mac"/></td>
<td><input value="{{ info.nombre if info.nombre else info.tipo }}" class="nombre"/></td>
<td>
<select class="emoji">
<option>📱</option><option>💻</option><option>🍓</option><option>📶</option><option>❓</option>
</select>
</td>
<td><input type="color" value="{{ info.color }}" class="color"/></td>
</tr>
{% endfor %}
</table>
<button onclick="guardar()">Guardar</button>
<script>
function guardar(){
    let filas=document.querySelectorAll("table")[0].querySelectorAll("tr");
    let tipos=[];
    filas.forEach((f,i)=>{
        if(i==0) return;
        let k=f.querySelector(".keywords").value.split(",");
        let tipo=f.querySelector(".tipo").value;
        let emoji=f.querySelector(".emoji").value;
        let color=f.querySelector(".color").value;
        tipos.push({keywords:k,tipo:tipo,icono:emoji,color:color});
    });
    let filas2=document.querySelectorAll("table")[1].querySelectorAll("tr");
    let macs={};
    filas2.forEach((f,i)=>{
        if(i==0) return;
        let mac=f.querySelector(".mac").value.toLowerCase();
        let nombre=f.querySelector(".nombre").value;
        let emoji=f.querySelector(".emoji").value;
        let color=f.querySelector(".color").value;
        if(mac) macs[mac]={nombre:nombre,tipo:nombre,icono:emoji,color:color};
    });
    fetch("/tipos",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tipos:tipos,macs:macs})}).then(r=>alert("Guardado"))
}
</script>
</body></html>
"""

@app.route("/tipos", methods=["GET","POST"])
def tipos_editor():
    if request.method=="POST":
        data=request.get_json()
        if "tipos" in data:
            _atomic_write(TIPOS_FILE,json.dumps(data["tipos"],ensure_ascii=False,indent=2).encode("utf-8"))
        if "macs" in data:
            _atomic_write(MACS_FILE,json.dumps(data["macs"],ensure_ascii=False,indent=2).encode("utf-8"))
        return "ok",200
    tipos=cargar_tipos()
    macs=cargar_macs()
    return render_template_string(PAGINA_TIPOS, tipos=tipos, macs=macs)

@app.route("/")
def dashboard():
    tabla="".join(
        f"<tr style='background-color:{d.get('color','#fff')}'>"
        f"<td>{d.get('ip')}</td><td>{d.get('tipo')}</td><td>{d.get('icono')}</td></tr>"
        for d in dispositivos
    )
    alerta_nuevos="".join(f"<li>{d.get('ip')} - {d.get('tipo')} {d.get('icono')}</li>" for d in nuevos_detectados)
    return f"""
<html><head><title>Dashboard</title></head>
<body>
<h2>Dispositivos detectados</h2>
<a href="/tipos">🧩 Configurar tipos de equipos / MACs especiales</a>
<table border=1>{tabla}</table>
<h3>Nuevos detectados</h3><ul>{alerta_nuevos}</ul>
</body></html>
"""

# ---------------- Main ----------------
if __name__=="__main__":
    dispositivos=cargar_estado()
    threading.Thread(target=lambda: [escanear_red() or time.sleep(30) for _ in iter(int,1)], daemon=True).start()
    app.run(host="0.0.0.0", port=5000)