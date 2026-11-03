# apk-analyzer

Herramienta de **análisis estático de seguridad para apps Android**. Recibe un archivo `.apk`, lo inspecciona sin ejecutarlo y genera un reporte de debilidades de seguridad y privacidad: permisos riesgosos, configuración insegura del manifest, componentes expuestos a otras apps y secretos escritos en el código.

Es una herramienta **defensiva**. No explota nada, no se conecta a ningún sistema y no modifica el APK. Su propósito es el mismo que el de los chequeos que se hacen antes de publicar una app o antes de aprobar su uso dentro de una empresa: detectar problemas a tiempo.

## Qué revisa

**Permisos riesgosos.** Compara los permisos que pide la app contra un catálogo propio, en el que cada permiso tiene un nivel (ALTO, MEDIO o BAJO) y una explicación del riesgo. Por ejemplo, `RECORD_AUDIO`, `READ_SMS`, `SYSTEM_ALERT_WINDOW` o `REQUEST_INSTALL_PACKAGES`.

**Configuración del manifest.** Revisa tres atributos de `<application>`:

- `debuggable`: si está en `true`, cualquiera puede conectar un depurador a la app en producción.
- `allowBackup`: si el atributo no aparece, Android lo toma como `true`. Por eso la herramienta revisa el valor efectivo y no solo el que está escrito.
- `usesCleartextTraffic`: el valor por defecto depende del SDK objetivo. Desde el SDK 28, el tráfico HTTP está bloqueado si la app no dice lo contrario.

**Componentes exportados sin permiso.** Detecta activities, services, receivers y providers que otras apps del teléfono pueden invocar sin necesitar ningún permiso. Para cada uno muestra las acciones de sus `intent-filter`, que explican *por qué* está expuesto. Las entradas del launcher se excluyen, porque necesitan estar exportadas para que la app se pueda abrir.

**Secretos en el código.** Busca en los strings de los archivos `.dex` y en el bundle de JavaScript de las apps React Native/Expo (`assets/index.android.bundle`, incluso compilado con Hermes) patrones de Google API keys, AWS access keys, llaves privadas, tokens JWT, URLs de Firebase y URLs y keys de Supabase (`sb_secret_` como ALTO, `sb_publishable_` como BAJO). El reporte muestra solo los primeros 10 caracteres de cada secreto encontrado, porque una herramienta de seguridad no debe filtrar los secretos que detecta.

## Instalación

Requiere Python 3 y [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/ignacioaguayluz/apk-analyzer.git
cd apk-analyzer
uv sync
```

## Uso

```bash
uv run main.py ruta/al/archivo.apk          # reporte en texto
uv run main.py ruta/al/archivo.apk --json   # reporte en JSON
uv run main.py ruta/al/archivo.apk --html reporte.html   # además guarda un reporte HTML
uv run main.py ruta/al/archivo.apk --fallar-en ALTO       # código 1 si hay hallazgos ALTO
```

El JSON tiene cuatro claves: `app` (paquete, nombre, versión y SDKs), `permisos` (todos los que pide la app), `resumen` (cantidad de hallazgos por nivel) y `hallazgos`. Cada hallazgo tiene siempre `categoria` (`permiso`, `manifest`, `componente` o `secreto`) y `nivel` (`ALTO`, `MEDIO` o `BAJO`), más los campos propios de su categoría. Los secretos se guardan solo con sus primeros 10 caracteres (`valor_parcial`).

```json
{
  "categoria": "secreto",
  "nivel": "BAJO",
  "tipo": "URL de Supabase",
  "valor_parcial": "https://mr",
  "origen": "bundle JS"
}
```

## Ejemplo: F-Droid 2.0.2

```
Paquete: org.fdroid.fdroid
Nombre:  F-Droid
Versión: 2.0.2
SDK mínimo: 24  |  SDK objetivo: 37

Hallazgos:
  [MEDIO] CAMERA: Acceso a la cámara
  [ALTO] MANAGE_EXTERNAL_STORAGE: Acceso a todo el almacenamiento compartido
  [MEDIO] QUERY_ALL_PACKAGES: Ve todas las apps instaladas (privacidad)
  [BAJO] READ_EXTERNAL_STORAGE: Lee archivos compartidos
  [BAJO] RECEIVE_BOOT_COMPLETED: Se ejecuta al encender el teléfono
  [ALTO] REQUEST_INSTALL_PACKAGES: Puede pedir instalar otras apps
  [MEDIO] WRITE_SETTINGS: Modifica ajustes del sistema

Configuración del manifest:
  [MEDIO] allowBackup activo: los datos de la app pueden incluirse en respaldos
  [MEDIO] Se permite tráfico HTTP sin cifrar

Componentes exportados sin permiso:
  [MEDIO] activity: org.fdroid.ui.panic.PanicActivity
      acciones: info.guardianproject.panic.action.CONNECT, info.guardianproject.panic.action.DISCONNECT
  [MEDIO] activity: org.fdroid.ui.panic.PanicResponderActivity
      acciones: info.guardianproject.panic.action.TRIGGER
  [MEDIO] activity: org.fdroid.MainActivity
      acciones: android.intent.action.MAIN, android.intent.action.SHOW_APP_INFO, android.intent.action.VIEW

Posibles secretos en el código:
  Ninguno encontrado.
```

(Se omitió la lista completa de permisos.)

### Cómo leer este resultado

Un hallazgo no significa que la app sea maliciosa. Significa que algo merece revisión, y el contexto decide si es un problema. En el caso de F-Droid:

- Los permisos para instalar paquetes, ver todas las apps y acceder al almacenamiento son los que necesita una **tienda de apps** para funcionar. En una app de linterna, serían una alarma.
- El tráfico HTTP está habilitado explícitamente, a pesar de que el SDK objetivo lo bloquearía por defecto. Es una decisión de diseño: F-Droid admite repositorios de terceros y el intercambio de apps por la red local, y verifica la integridad de las apps con firmas criptográficas, no con el cifrado del canal.
- Las actividades de pánico están expuestas a propósito. Implementan **PanicKit**, de Guardian Project, que permite que una app de "botón de pánico" le pida a F-Droid ocultarse o borrar datos.
- `MainActivity` recibe enlaces externos (`VIEW`) y la acción `SHOW_APP_INFO`, que es como Android le pide a una tienda que muestre la información de una app.

## Decisiones de diseño

- **Valores efectivos, no solo declarados.** Varios atributos de Android tienen valores por defecto que cambian según la versión. Revisar solo lo que está escrito produce falsos negativos.
- **Evidencia junto al hallazgo.** Los componentes exportados se muestran con sus acciones, para que quien revisa pueda decidir sin abrir el manifest.
- **Varias entradas al launcher.** Algunas apps tienen varios `activity-alias` como launcher (F-Droid puede disfrazarse de calculadora). Por eso se excluye cualquier componente con la categoría `LAUNCHER`, en lugar de comparar contra una única actividad principal.
- **Supabase: secret vs. publishable.** La secret key salta las políticas RLS y nunca debe ir en una app, así que es ALTO. La publishable key es pública por diseño, así que es BAJO. El patrón de la secret key exige un carácter alfanumérico después del prefijo, porque Expo Router incluye el identificador interno `sb_secret__internal_expo_router_...`, que de otro modo sería un falso positivo.
- **JWT como MEDIO.** Algunos tokens están hechos para ser públicos, como la *anon key* de Supabase, cuya seguridad depende de las políticas RLS y no de que la llave esté oculta.

### Uso en CI

`--fallar-en NIVEL` hace que la herramienta termine con código de salida `1` si hay al menos un hallazgo de ese nivel o uno más grave (`MEDIO` incluye `ALTO` y `MEDIO`). Así el pipeline se detiene antes de publicar la app. Sin la opción, la herramienta siempre termina con `0`. Un argumento inválido termina con `2`.

| Código | Significado |
| --- | --- |
| `0` | Sin hallazgos en el umbral (o sin `--fallar-en`) |
| `1` | Hay hallazgos del nivel indicado o más graves |
| `2` | Error de uso (argumentos inválidos) |

El reporte HTML es un solo archivo sin dependencias externas, con modo claro y oscuro. Todo texto que viene del APK se escapa con `html.escape`, porque un APK malicioso podría traer etiquetas en sus nombres de componentes y convertir el reporte en un vector de XSS.

## Limitaciones conocidas

- No lee `network_security_config`, que puede permitir HTTP solo para ciertos dominios.
- No busca secretos en los recursos (`strings.xml`) ni en assets distintos del bundle de React Native.
- No detecta providers exportados de forma implícita en apps con SDK objetivo antiguo (16 o menos).
- Los patrones de secretos cubren solo unos pocos proveedores.

## Próximos pasos

- [x] Reporte en JSON
- [x] Reporte en HTML
- [x] Exit code para CI (`--fallar-en`)
- [ ] Workflow de GitHub Actions de ejemplo
- [ ] Leer `network_security_config`
- [x] Buscar secretos en el bundle de React Native
- [ ] Buscar secretos en los recursos (`strings.xml`)
- [ ] Más patrones de secretos
- [ ] Probar contra una app vulnerable de práctica (InsecureBankv2)

## Uso responsable

Esta herramienta es para analizar apps propias, apps open source o apps sobre las que tengas autorización. Su objetivo es encontrar y corregir problemas, no aprovecharlos.
