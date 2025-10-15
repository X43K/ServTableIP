import sys

# Nombre del archivo ejecutado (intento robusto usando __file__ o sys.argv)
try:
    _APP_FILENAME = Path(__file__).name
except Exception:
    _APP_FILENAME = Path(sys.argv[0]).name if len(sys.argv) > 0 else "unknown"

def _format_app_display(filename: str) -> str:
    """
    Convierte "ServTableIP-5.0.py" -> "ServTableIP v.5.0"
    Maneja separadores -, _, espacio, y prefijo 'v' opcional.
    Si no detecta versión, devuelve el nombre sin extensión.
    """
    stem = Path(filename).stem  # quita la extensión
    # patrón: base (-|_| ) v?version (version puede ser 1, 1.2, 1_2, 1.2.3...)
    m = re.match(r'^(.+?)[\-\_\s]+v?(\d+(?:[._]\d+)*)$', stem, flags=re.I)
    if m:
        base = m.group(1)
        ver = m.group(2).replace('_', '.')
        return f"{base} v.{ver}"
    # si no encaja el patrón, devolver el stem tal cual
    return stem

APP_DISPLAY_NAME = _format_app_display(_APP_FILENAME)