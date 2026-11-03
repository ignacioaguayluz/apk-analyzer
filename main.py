import argparse
import json
import sys
from loguru import logger
from androguard.core.apk import APK

from apk_analyzer.reporte import NIVELES, analizar
from apk_analyzer.salida_html import generar_html
from apk_analyzer.salida_texto import imprimir_texto

logger.remove()


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
