import argparse
import html
import json
import sys
from loguru import logger
from androguard.core.apk import APK

from apk_analyzer.reporte import NIVELES, analizar, de_categoria
from apk_analyzer.salida_texto import imprimir_texto

logger.remove()


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
        print(f"Reporte HTML guardado en {args.html}", file=sys.stderr)

    if args.json:
        print(json.dumps(reporte, ensure_ascii=False, indent=2))
    else:
        imprimir_texto(reporte)

    if args.fallar_en:
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
