from apk_analyzer.componentes import revisar_componentes
from apk_analyzer.manifest import PERMISOS_RIESGOSOS, revisar_manifest
from apk_analyzer.secretos import buscar_secretos

NIVELES = ["ALTO", "MEDIO", "BAJO"]


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
