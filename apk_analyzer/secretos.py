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
    "Supabase secret key": (r"sb_secret_[A-Za-z0-9][A-Za-z0-9_-]{20,}", "ALTO"),
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

    if BUNDLE_REACT_NATIVE in apk.get_files():
        bundle = apk.get_file(BUNDLE_REACT_NATIVE).decode("latin-1")
        hallazgos |= secretos_en_texto(bundle, "bundle JS")

    return sorted(hallazgos)
