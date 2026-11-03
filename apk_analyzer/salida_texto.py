from apk_analyzer.reporte import de_categoria


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
