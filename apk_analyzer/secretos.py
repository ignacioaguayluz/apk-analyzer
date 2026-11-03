import re

from androguard.core.dex import DEX


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
