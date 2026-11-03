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
