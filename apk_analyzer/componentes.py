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
