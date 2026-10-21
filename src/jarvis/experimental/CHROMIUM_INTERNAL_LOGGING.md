# Logging interno del diagnóstico sintético

Se añade `logging_mode`, con valores `disabled` (predeterminado) y `verbose`.
Solo puede elegirse al preparar un bundle. `verbose` exige `environment_mode=minimal`
y `job_launch_mode=job_list`; otras combinaciones se rechazan antes de acceder al
runtime. `run` no admite sobreescribir estas opciones. Los manifiestos nuevos
fijan también `max_internal_log_bytes=1048576`. Los anteriores sin esos campos
se conservan como evidencia; no se modifican, migran ni reutilizan.

Chromium documenta `--enable-logging --v=1` para obtener un log de depuración.
Sus registros pueden contener URLs y datos personales; stderr de Windows no
recoge necesariamente toda la salida de procesos sandboxed.
[Guía oficial de Chromium](https://www.chromium.org/for-testers/enable-logging/).

El modo añade únicamente esos dos argumentos y
`--log-file=<ruta-absoluta-de-session\logs\chrome_debug.log>`. La ruta se genera
en código y no se acepta una ruta de log en el manifiesto, CLI o entorno.
Se mantiene `subprocess.list2cmdline`, sin introducir comillas manuales dentro
de los argumentos. Una prueba con `CommandLineToArgvW` comprueba su separación,
incluidas rutas con espacios.

El código upstream de Chromium prioriza `--log-file` sobre `CHROME_LOG_FILE` y
requiere ruta absoluta en Windows. Los builds release usan el archivo como
destino predeterminado; builds Debug pueden emitir a otros destinos. Este
procedimiento corresponde al runtime release revisado, no a builds Debug
arbitrarios. No se afirma cobertura completa de todos los procesos internos ni
aislamiento de trazas del sistema.
[Chromium: logging_chrome.cc](https://github.com/chromium/chromium/blob/main/chrome/common/logging_chrome.cc).

## Controles y límites

La sesión y su directorio `logs` se crean nuevos y se mantienen fijados por
handles de directorio sin compartir borrado, con los controles existentes contra
reparse points. No se cambian ACL. El archivo de logging lo crea Chromium;
no se heredan handles adicionales desde el supervisor.

Se conservan las ocho variables de `minimal`, sin `CHROME_LOG_FILE`, secretos,
proxies ni overrides heredados. Tampoco se modifican el HTML/CSP, data URL,
sandbox, `job_list`, límites `0x2008`/64 procesos, suspensión y verificación antes
de reanudar, identidad del operador estándar, hash aprobado y fijación del
runtime, redirección de stdout/stderr, plazos de 30/6 segundos o watchdog de 46.
Producción y navegación pública permanecen bloqueadas.

| Control | Comportamiento |
| --- | --- |
| Umbral del log | 1 MiB; se comprueba su tamaño durante la vigilancia, sin leer contenido |
| Si excede el umbral | `internal_log_limit`, se interrumpe la vigilancia y se intenta cerrar el Job |
| Si no puede verificarse/abrirse | `internal_log_unreadable`; se conserva el error sin mensaje del SO |
| Lectura para categorizar | Como máximo 1 MiB + un byte centinela; solo se categoriza el primer MiB |
| Tamaño en informe | Entre 0 y 1048576, con `size_capped=true` si se observó un exceso |
| Salida inmediata con log excesivo | También se detecta después del cierre; impide declarar éxito funcional |
| Limpieza incierta o watchdog | `not_inspected`; no se lee el log ni se afirma su ausencia |

El umbral es una parada por muestreo, **no una cuota de disco**: el archivo bruto
puede superar 1 MiB entre sondeos o durante el cierre. No se trunca ni elimina
evidencia automáticamente. Permanecen los límites previos de DOM (64 KiB) y
stderr (256 KiB). El directorio privado de la sesión no constituye una nueva
frontera de permisos frente a procesos con la misma identidad.

La lectura del log usa `FILE_FLAG_OPEN_REPARSE_POINT`, verifica la ruta final del
handle antes de leer y acepta solo un archivo regular con un único enlace.
Se rechazan enlaces duros, reparse points y destinos cambiados. Los handles de
lectura no son heredables y se cierran al terminar; no se solicitan permisos de
escritura sobre el log para inspeccionarlo.

## Informe y revisión sanitizada

El informe añade `logging_mode` e `internal_log`, que contiene exclusivamente:

```json
{
  "presence": "present",
  "size_bytes": 1234,
  "size_capped": false,
  "categories": ["network_service_crash_reported"]
}
```

`presence` distingue `disabled`, `not_inspected`, `missing`, `present` y
`unreadable`; el tamaño es null cuando no puede afirmarse. `present` con tamaño
cero no significa inicialización completa. Las categorías fijas describen
indicios de crash del servicio de red, acceso denegado, sandbox, handle, Job,
inicialización, carga de bibliotecas, IPC y error fatal. No incluyen mensajes,
nombres, rutas, URLs, SID, tokens, timestamps ni fragmentos de líneas.
La ausencia de categorías tampoco descarta fallos: solo se analiza el prefijo
acotado y una lista de expresiones conocidas.

`inspect-log --bundle <ruta>` valida el manifiesto y el informe, contrasta los
modos y vuelve a obtener únicamente esos metadatos/categorías. No lanza procesos,
no escribe archivos y no imprime el log bruto. Si la limpieza no está verificada,
devuelve `not_inspected` y código 2; con archivo ilegible o excesivo también
devuelve código 2. Las reservas, perfiles y registros se conservan.

## Bundle único preparado, todavía sin ejecutar

`E:\JARVIS\chromium-diagnostic-review-640176dc7bdb409ab93d830bf732b382`

[Manifiesto](../../../chromium-diagnostic-review-640176dc7bdb409ab93d830bf732b382/manifest.json).
Se preparó en `minimal`, `job_list`, `verbose`, con la ruta exacta ya permitida
de Playwright `chromium-1208\chrome-win64\chrome.exe`. No se accedió al binario
ni se aprobó un hash automáticamente. El bundle solo contiene `manifest.json`
y el HTML sintético intacto; no tiene sesión, reserva, informe ni registros.

Para ejecutarlo **posteriormente**, desde la sesión normal del operador y con
el SHA-256 del runtime previamente revisado y aprobado, ejecutar exactamente:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath 'E:\JARVIS'
$PythonDiagnostico = 'E:\JARVIS\.venv\Scripts\python.exe'
$ScriptDiagnostico = 'E:\JARVIS\tools\experimental\run_chromium_diagnostic.py'
$BundleLogging = 'E:\JARVIS\chromium-diagnostic-review-640176dc7bdb409ab93d830bf732b382'
$HashChromiumAprobado = '<sha256-previamente-revisada-y-aprobada>'
if ($HashChromiumAprobado -cnotmatch '^[a-f0-9]{64}$') {
    throw 'Sustituir el marcador por el SHA-256 aprobado; no ejecutar sin revisarlo.'
}
$SalidaLogging = & $PythonDiagnostico $ScriptDiagnostico run --bundle $BundleLogging --approved-chromium-sha256 $HashChromiumAprobado --acknowledge-diagnostic-only
$CodigoLogging = $LASTEXITCODE
$ResultadoLogging = $SalidaLogging | ConvertFrom-Json
$ResultadoLogging | Select-Object status, wait_outcome, dom_status, exit_code, cleanup_verified, logging_mode
if ($ResultadoLogging.cleanup_verified -ne $true) {
    throw 'Limpieza incierta o ejecución denegada: conservar reserva y evidencia; revisión manual antes de continuar.'
}
# Un wall_timeout con limpieza verificada suele devolver 2 y puede inspeccionarse.
$CodigoLogging
& $PythonDiagnostico $ScriptDiagnostico inspect-log --bundle $BundleLogging
$CodigoInspeccionLogging = $LASTEXITCODE
if ($CodigoInspeccionLogging -ne 0) {
    throw 'Inspección incompleta o log excesivo/ilegible; conservar evidencia y revisar el resultado sanitizado.'
}
```

El registro bruto, si llega a crearse, estará en
`<bundle>\session\logs\chrome_debug.log`. Para compartir resultados usar la
salida sanitizada de `inspect-log` y los campos acotados del informe. No usar
`Get-Content`, `type`, `cat` ni adjuntar el archivo bruto, DOM, stderr o perfil a
la conversación. Si hiciera falta revisar líneas concretas, hacerlo localmente
después de verificar la limpieza y retirar datos personales antes de compartir
un extracto. No reejecutar este bundle ni borrar su reserva para repetir.

## Verificación realizada

```powershell
& 'E:\JARVIS\.venv\Scripts\python.exe' -m pytest -q tests\test_chromium_diagnostic.py tests\test_browser_run_environment.py tests\test_browser_chromium_sid_lab.py
```

Resultado: **128 pruebas y 386 subpruebas correctas**. Los lanzamientos de
Chromium, asociaciones y cierres del navegador se simulan. También se comprueban
archivos temporales reales, metadatos de enlaces, quoting de Windows y lecturas
locales ya existentes de tokens/descriptores; no se ha probado una emisión real
de logs de Chromium ni resuelto la causa del timeout. No se han cambiado ACL,
firewall, otros experimentos ni se han hecho commits.
