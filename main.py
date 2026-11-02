import sys
from loguru import logger
from androguard.core.apk import APK
import re
from androguard.core.dex import DEX

logger.remove()

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


def main():
    if len(sys.argv) != 2:
        print("Uso: uv run main.py ruta/al/archivo.apk")
        sys.exit(1)

    apk = APK(sys.argv[1])

    print(f"Paquete: {apk.get_package()}")
    print(f"Nombre:  {apk.get_app_name()}")
    print(f"Versión: {apk.get_androidversion_name()}")
    print(
        f"SDK mínimo: {apk.get_min_sdk_version()}  |  SDK objetivo: {apk.get_target_sdk_version()}"
    )

    print("\nPermisos:")
    for permiso in sorted(apk.get_permissions()):
        print(f"  - {permiso}")

    print("\nHallazgos:")
    hallazgos = 0
    for permiso in sorted(apk.get_permissions()):
        if permiso in PERMISOS_RIESGOSOS:
            nivel, motivo = PERMISOS_RIESGOSOS[permiso]
            print(f"  [{nivel}] {permiso.split('.')[-1]}: {motivo}")
            hallazgos += 1

    if hallazgos == 0:
        print("  Ningún permiso de la lista de riesgo.")

    print("\nConfiguración del manifest:")
    problemas = revisar_manifest(apk)
    for nivel, motivo in problemas:
        print(f"  [{nivel}] {motivo}")
    if not problemas:
        print("  Sin problemas de configuración.")

    print("\nComponentes exportados sin permiso:")
    componentes = revisar_componentes(apk)
    for tipo, nombre, acciones in componentes:
        nivel = "ALTO" if tipo == "provider" else "MEDIO"
        print(f"  [{nivel}] {tipo}: {nombre}")
        if acciones:
            print(f"      acciones: {', '.join(acciones)}")

    print("\nPosibles secretos en el código:")
    secretos = buscar_secretos(apk)
    for nivel, nombre, valor, origen in secretos:
        print(f"  [{nivel}] {nombre} ({origen}): {valor[:10]}...")
    if not secretos:
        print("  Ninguno encontrado.")


if __name__ == "__main__":
    main()
