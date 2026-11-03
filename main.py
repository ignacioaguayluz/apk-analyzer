import argparse
import html
import json
import sys
from loguru import logger
from androguard.core.apk import APK
import re
from androguard.core.dex import DEX

logger.remove()

NIVELES = ["ALTO", "MEDIO", "BAJO"]

PERMISOS_RIESGOSOS = {
    "android.permission.RECORD_AUDIO": ("ALTO", "Puede grabar audio con el micrófono"),
    "android.permission.ACCESS_FINE_LOCATION": ("ALTO", "Ubicación precisa por GPS"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "ALTO",
        "Ubicación incluso con la app cerrada",
    ),
    "android.permission.READ_SMS": (
        "ALTO",
        "Lee mensajes SMS, incluidos códigos de verificación",
    ),
    "android.permission.SEND_SMS": (
        "ALTO",
        "Puede enviar SMS, posible costo para el usuario",
    ),
    "android.permission.READ_CALL_LOG": ("ALTO", "Lee el historial de llamadas"),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "ALTO",
        "Dibuja encima de otras apps; usado para pantallas falsas",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "ALTO",
        "Puede pedir instalar otras apps",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "ALTO",
        "Acceso a todo el almacenamiento compartido",
    ),
    "android.permission.CAMERA": ("MEDIO", "Acceso a la cámara"),
    "android.permission.READ_CONTACTS": ("MEDIO", "Lee la lista de contactos"),
    "android.permission.QUERY_ALL_PACKAGES": (
        "MEDIO",
        "Ve todas las apps instaladas (privacidad)",
    ),
    "android.permission.WRITE_SETTINGS": ("MEDIO", "Modifica ajustes del sistema"),
    "android.permission.READ_EXTERNAL_STORAGE": ("BAJO", "Lee archivos compartidos"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "BAJO",
        "Se ejecuta al encender el teléfono",
    ),
}


def revisar_manifest(apk):
    hallazgos = []

    if apk.get_attribute_value("application", "debuggable") == "true":
        hallazgos.append(
            (
                "ALTO",
                "debuggable=true: se puede conectar un depurador e inspeccionar la app en ejecución",
            )
        )

    if apk.get_attribute_value("application", "allowBackup") != "false":
        hallazgos.append(
            (
                "MEDIO",
                "allowBackup activo: los datos de la app pueden incluirse en respaldos",
            )
        )

    cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
    target = int(apk.get_target_sdk_version() or 0)
    if cleartext == "true" or (cleartext is None and target < 28):
        hallazgos.append(("MEDIO", "Se permite tráfico HTTP sin cifrar"))

    return hallazgos


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def es_launcher(componente):
    for categoria in componente.iter("category"):
        if categoria.get(ANDROID_NS + "name") == "android.intent.category.LAUNCHER":
            return True
    return False


def revisar_componentes(apk):
    hallazgos = []
    manifest = apk.get_android_manifest_xml()

    for tipo in ["activity", "activity-alias", "service", "receiver", "provider"]:
        for componente in manifest.iter(tipo):
            nombre = componente.get(ANDROID_NS + "name")
            exportado = componente.get(ANDROID_NS + "exported")
            permiso = componente.get(ANDROID_NS + "permission")
            tiene_filtro = componente.find("intent-filter") is not None

            if exportado == "false":
                continue
            if exportado is None and not tiene_filtro:
                continue
            if permiso is not None:
                continue
            if es_launcher(componente):
                continue

            acciones = sorted(
                {a.get(ANDROID_NS + "name") for a in componente.iter("action")}
            )
            hallazgos.append((tipo, nombre, acciones))

    return hallazgos


PATRONES_SECRETOS = {
    "Google API key": (r"AIza[0-9A-Za-z\-_]{35}", "ALTO"),
    "AWS access key": (r"AKIA[0-9A-Z]{16}", "ALTO"),
    "Llave privada": (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "ALTO"),
    "Token JWT": (
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "MEDIO",
    ),
    "Base de datos Firebase": (r"https://[a-z0-9-]+\.firebaseio\.com", "BAJO"),
    # La secret key salta las políticas RLS: nunca debe estar en una app.
    # Exigir un carácter alfanumérico tras el prefijo evita falsos positivos
    # como "sb_secret__internal_expo_router_..." (identificador de Expo Router).
    "Supabase secret key": (r"sb_secret_[A-Za-z0-9][A-Za-z0-9_-]{20,}", "ALTO"),
    # La publishable key es pública por diseño; su seguridad depende de RLS.
    "Supabase publishable key": (r"sb_publishable_[A-Za-z0-9_-]{20,}", "BAJO"),
    "URL de Supabase": (r"https://[a-z0-9-]+\.supabase\.co", "BAJO"),
}


BUNDLE_REACT_NATIVE = "assets/index.android.bundle"


def secretos_en_texto(texto, origen):
    hallazgos = set()
    for nombre, (patron, nivel) in PATRONES_SECRETOS.items():
        for coincidencia in re.finditer(patron, texto):
            hallazgos.add((nivel, nombre, coincidencia.group(0), origen))
    return hallazgos


def buscar_secretos(apk):
    hallazgos = set()

    for dex_bytes in apk.get_all_dex():
        for texto in DEX(dex_bytes).get_strings():
            hallazgos |= secretos_en_texto(texto, "dex")

    # React Native/Expo: el JS vive en este asset. Con Hermes es bytecode, pero
    # los literales de texto se guardan como bytes planos y la regex los encuentra.
    # latin-1 convierte cada byte en un carácter, así que decodificar nunca falla.
    if BUNDLE_REACT_NATIVE in apk.get_files():
        bundle = apk.get_file(BUNDLE_REACT_NATIVE).decode("latin-1")
        hallazgos |= secretos_en_texto(bundle, "bundle JS")

    return sorted(hallazgos)


def analizar(apk):
    target = apk.get_target_sdk_version()
    minimo = apk.get_min_sdk_version()
    hallazgos = []

    for permiso in sorted(apk.get_permissions()):
        if permiso in PERMISOS_RIESGOSOS:
            nivel, motivo = PERMISOS_RIESGOSOS[permiso]
            hallazgos.append(
                {"categoria": "permiso", "nivel": nivel, "permiso": permiso, "motivo": motivo}
            )

    for nivel, motivo in revisar_manifest(apk):
        hallazgos.append({"categoria": "manifest", "nivel": nivel, "motivo": motivo})

    for tipo, nombre, acciones in revisar_componentes(apk):
        hallazgos.append(
            {
                "categoria": "componente",
                "nivel": "ALTO" if tipo == "provider" else "MEDIO",
                "tipo": tipo,
                "nombre": nombre,
                "acciones": acciones,
            }
        )

    # Solo se guardan los primeros 10 caracteres: el reporte no debe filtrar el secreto.
    for nivel, nombre, valor, origen in buscar_secretos(apk):
        hallazgos.append(
            {
                "categoria": "secreto",
                "nivel": nivel,
                "tipo": nombre,
                "valor_parcial": valor[:10],
                "origen": origen,
            }
        )

    return {
        "app": {
            "paquete": apk.get_package(),
            "nombre": apk.get_app_name(),
            "version": apk.get_androidversion_name(),
            "sdk_minimo": int(minimo) if minimo else None,
            "sdk_objetivo": int(target) if target else None,
        },
        "permisos": sorted(apk.get_permissions()),
        "resumen": {
            nivel: sum(1 for h in hallazgos if h["nivel"] == nivel)
            for nivel in NIVELES
        },
        "hallazgos": hallazgos,
    }


def de_categoria(reporte, categoria):
    return [h for h in reporte["hallazgos"] if h["categoria"] == categoria]


def imprimir_texto(reporte):
    app = reporte["app"]
    print(f"Paquete: {app['paquete']}")
    print(f"Nombre:  {app['nombre']}")
    print(f"Versión: {app['version']}")
    print(f"SDK mínimo: {app['sdk_minimo']}  |  SDK objetivo: {app['sdk_objetivo']}")

    print("\nPermisos:")
    for permiso in reporte["permisos"]:
        print(f"  - {permiso}")

    print("\nHallazgos:")
    permisos = de_categoria(reporte, "permiso")
    for h in permisos:
        print(f"  [{h['nivel']}] {h['permiso'].split('.')[-1]}: {h['motivo']}")
    if not permisos:
        print("  Ningún permiso de la lista de riesgo.")

    print("\nConfiguración del manifest:")
    problemas = de_categoria(reporte, "manifest")
    for h in problemas:
        print(f"  [{h['nivel']}] {h['motivo']}")
    if not problemas:
        print("  Sin problemas de configuración.")

    print("\nComponentes exportados sin permiso:")
    for h in de_categoria(reporte, "componente"):
        print(f"  [{h['nivel']}] {h['tipo']}: {h['nombre']}")
        if h["acciones"]:
            print(f"      acciones: {', '.join(h['acciones'])}")

    print("\nPosibles secretos en el código:")
    secretos = de_categoria(reporte, "secreto")
    for h in secretos:
        print(f"  [{h['nivel']}] {h['tipo']} ({h['origen']}): {h['valor_parcial']}...")
    if not secretos:
        print("  Ninguno encontrado.")


TITULOS_CATEGORIA = {
    "permiso": "Permisos riesgosos",
    "manifest": "Configuración del manifest",
    "componente": "Componentes exportados sin permiso",
    "secreto": "Posibles secretos en el código",
}


def describir(h):
    """Devuelve (título, detalle) en texto plano para cualquier hallazgo."""
    if h["categoria"] == "permiso":
        return h["permiso"].split(".")[-1], h["motivo"]
    if h["categoria"] == "manifest":
        return "Atributo de <application>", h["motivo"]
    if h["categoria"] == "componente":
        acciones = ", ".join(h["acciones"]) or "sin acciones declaradas"
        return f"{h['tipo']}: {h['nombre']}", f"acciones: {acciones}"
    return h["tipo"], f"{h['valor_parcial']}… (encontrado en {h['origen']})"


ESTILOS_HTML = """
:root { --fondo:#f7f7f8; --tarjeta:#fff; --texto:#1d1d20; --suave:#5f5f68; --borde:#e2e2e6;
  --alto:#c62828; --medio:#b26a00; --bajo:#2e6bb0; }
@media (prefers-color-scheme: dark) { :root { --fondo:#141416; --tarjeta:#1d1d21; --texto:#ececef;
  --suave:#a1a1aa; --borde:#2e2e34; --alto:#ef5350; --medio:#ffb74d; --bajo:#64b5f6; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--fondo); color:var(--texto);
  font:15px/1.5 system-ui, sans-serif; }
main { max-width:900px; margin:0 auto; }
h1 { margin:0 0 4px; font-size:24px; }
h2 { margin:32px 0 8px; font-size:18px; }
.suave { color:var(--suave); }
.resumen { display:flex; gap:12px; flex-wrap:wrap; margin:20px 0; }
.cifra { background:var(--tarjeta); border:1px solid var(--borde); border-radius:8px;
  padding:12px 16px; min-width:110px; }
.cifra b { display:block; font-size:26px; }
table { width:100%; border-collapse:collapse; background:var(--tarjeta);
  border:1px solid var(--borde); border-radius:8px; overflow:hidden; }
td { padding:10px 12px; border-top:1px solid var(--borde); vertical-align:top; overflow-wrap:anywhere; }
tr:first-child td { border-top:none; }
.nivel { font-weight:700; font-size:12px; white-space:nowrap; }
.ALTO { color:var(--alto); } .MEDIO { color:var(--medio); } .BAJO { color:var(--bajo); }
code { font-family:ui-monospace, monospace; font-size:13px; }
details { margin-top:32px; }
"""


def generar_html(reporte):
    # Todo texto que viene del APK pasa por html.escape: un APK malicioso podría
    # traer etiquetas en sus nombres y convertir el reporte en un ataque XSS.
    e = html.escape
    app = reporte["app"]
    partes = [
        "<!doctype html>",
        '<html lang="es"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Reporte de seguridad: {e(str(app['nombre']))}</title>",
        f"<style>{ESTILOS_HTML}</style></head><body><main>",
        f"<h1>{e(str(app['nombre']))}</h1>",
        f'<p class="suave"><code>{e(str(app["paquete"]))}</code> · versión {e(str(app["version"]))}'
        f" · SDK mínimo {e(str(app['sdk_minimo']))} · SDK objetivo {e(str(app['sdk_objetivo']))}</p>",
        '<div class="resumen">',
    ]
    for nivel, cantidad in reporte["resumen"].items():
        partes.append(f'<div class="cifra"><b class="{nivel}">{cantidad}</b>{nivel}</div>')
    partes.append("</div>")

    for categoria, titulo in TITULOS_CATEGORIA.items():
        hallazgos = de_categoria(reporte, categoria)
        partes.append(f"<h2>{titulo}</h2>")
        if not hallazgos:
            partes.append('<p class="suave">Sin hallazgos.</p>')
            continue
        partes.append("<table>")
        for h in hallazgos:
            nombre, detalle = describir(h)
            partes.append(
                f'<tr><td class="nivel {h["nivel"]}">{h["nivel"]}</td>'
                f"<td><code>{e(nombre)}</code><br>"
                f'<span class="suave">{e(detalle)}</span></td></tr>'
            )
        partes.append("</table>")

    partes.append(f"<details><summary>Todos los permisos ({len(reporte['permisos'])})</summary><ul>")
    for permiso in reporte["permisos"]:
        partes.append(f"<li><code>{e(permiso)}</code></li>")
    partes.append("</ul></details>")
    partes.append(
        '<p class="suave">Un hallazgo no significa que la app sea maliciosa: '
        "indica algo que merece revisión según el contexto de la app.</p>"
    )
    partes.append("</main></body></html>")
    return "\n".join(partes)


def main():
    parser = argparse.ArgumentParser(
        description="Análisis estático de seguridad para APKs de Android."
    )
    parser.add_argument("apk", help="ruta al archivo .apk")
    parser.add_argument(
        "--json", action="store_true", help="imprime el reporte en formato JSON"
    )
    parser.add_argument(
        "--html", metavar="ARCHIVO", help="además guarda un reporte HTML en ARCHIVO"
    )
    parser.add_argument(
        "--fallar-en",
        choices=NIVELES,
        help="termina con código 1 si hay hallazgos de este nivel o uno más grave (para CI)",
    )
    args = parser.parse_args()

    reporte = analizar(APK(args.apk))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as archivo:
            archivo.write(generar_html(reporte))
        # Va a stderr para no ensuciar la salida JSON si se combinan las opciones.
        print(f"Reporte HTML guardado en {args.html}", file=sys.stderr)

    if args.json:
        print(json.dumps(reporte, ensure_ascii=False, indent=2))
    else:
        imprimir_texto(reporte)

    if args.fallar_en:
        # NIVELES va de más a menos grave: "MEDIO" incluye ALTO y MEDIO.
        graves = NIVELES[: NIVELES.index(args.fallar_en) + 1]
        total = sum(reporte["resumen"][nivel] for nivel in graves)
        if total:
            print(
                f"Falla: {total} hallazgo(s) de nivel {args.fallar_en} o más grave",
                file=sys.stderr,
            )
            sys.exit(1)


if __name__ == "__main__":
    main()
