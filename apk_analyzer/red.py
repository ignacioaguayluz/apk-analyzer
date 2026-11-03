from androguard.core.axml import AXMLPrinter

NOMBRE_ATRIBUTO = "networkSecurityConfig"


def leer_config_red(apk):
    referencia = apk.get_attribute_value("application", NOMBRE_ATRIBUTO)
    if not referencia or not referencia.startswith("@"):
        return None
    try:
        recursos = apk.get_android_resources()
        ruta = recursos.get_resolved_res_configs(int(referencia[1:], 16))[0][1]
        return AXMLPrinter(apk.get_file(ruta)).get_xml_obj()
    except Exception:
        return None


def revisar_config_red(apk):
    raiz = leer_config_red(apk)
    if raiz is None:
        return []

    hallazgos = []

    base = raiz.find("base-config")
    if base is not None:
        if base.get("cleartextTrafficPermitted") == "true":
            hallazgos.append(
                ("MEDIO", "network_security_config permite HTTP sin cifrar en toda la app")
            )
        for certificados in base.iterfind("trust-anchors/certificates"):
            if certificados.get("src") == "user":
                hallazgos.append(
                    ("MEDIO", "network_security_config confía en certificados instalados por el usuario")
                )

    for dominio in raiz.iterfind("domain-config"):
        if dominio.get("cleartextTrafficPermitted") == "true":
            nombres = sorted(d.text for d in dominio.iterfind("domain") if d.text)
            hallazgos.append(
                ("BAJO", f"network_security_config permite HTTP para: {', '.join(nombres)}")
            )

    return hallazgos
