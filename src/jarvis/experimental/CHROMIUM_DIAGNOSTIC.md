# Diagnóstico local de Chromium con HTML sintético

El logging interno opcional, desactivado por defecto, su bundle nuevo y los
comandos de ejecución y revisión sanitizada se describen en
[CHROMIUM_INTERNAL_LOGGING.md](CHROMIUM_INTERNAL_LOGGING.md).

La investigación del supervisor, sus límites y la comparación de asociación
atómica frente a asignación suspendida con guardia se documentan en
[CHROMIUM_JOB_OBJECTS.md](CHROMIUM_JOB_OBJECTS.md). Esa comparación mantiene fijo
el entorno y usa tres bundles nuevos, independientes de los pares de entorno
descritos aquí. No se ha ejecutado Chromium durante esta investigación.

Este modo está separado de producción, de los lanzadores SID anteriores y de
AppContainer. No concede autorización de producción. No evalúa aislamiento del
repositorio, del sistema de archivos ni de la red. Todos los informes contienen
`production_launch_allowed=false` e `isolation_verified=false`.

No instala ni activa políticas, cuentas, reglas de firewall o ACL. No pide ni
acepta contraseñas, no cambia de identidad y no usa runas. Solo admite una sesión
normal del operador actual; rechaza la cuenta restringida jarvis_browser_lab y
tokens elevados. No hay fallback a otra identidad. No ejecutar el diagnóstico
desde esa cuenta restringida.

## Qué cambia respecto al camino experimental anterior

El timeout y el DOM vacío observados anteriormente no tienen todavía una causa
real confirmada. Se han identificado y corregido caminos que impedían obtener
un diagnóstico fiable, sin modificar aquel experimento:

- La consulta WMI global precedía a la comprobación de salida del proceso y podía
  consumir el plazo o fallar independientemente del navegador. Ahora se comprueba
  primero el handle raíz y se usa un plazo monotónico. No hay WMI ni enumeración
  del sistema. Solo se consultan el Job propio y su puerto de notificaciones.
- El timeout de captura de Chrome y el presupuesto de tiempo virtual no son el
  timeout del proceso. Se fijan respectivamente en 5 s, 1 s y 30 s de plazo real.
  La limpieza tiene un presupuesto adicional de 6 s. El padre Python aplica un
  watchdog de 46 s que incluye arranque, inspección y limpieza.
- Se usa CreateProcessW bajo la identidad actual, con proceso suspendido,
  STARTUPINFOEX y una lista explícita de los tres handles heredados: NUL como
  stdin, dom.txt como stdout y stderr.txt como stderr. La consola y otros handles
  del controlador no se incluyen. La asignación al Job se hace atómicamente al
  crear el proceso mediante PROC_THREAD_ATTRIBUTE_JOB_LIST: el watchdog no deja
  una raíz suspendida pendiente de asignación. Requiere Windows 10 o posterior;
  un fallo no usa una alternativa. Job e identidad raíz se verifican antes de
  ResumeThread. No se usa el antiguo mecanismo de logon/redirección.
- La falta de acceso a un token hijo se registra como identidad desconocida y
  conserva su código. No equivale a otra identidad ni a aislamiento comprobado.
  Se solicita exclusivamente PROCESS_QUERY_LIMITED_INFORMATION y TOKEN_QUERY.
  No se solicita VM_READ ni se amplían privilegios o permisos.
- Los PIDs proceden del Job, con generaciones separadas si se reutilizan tras un
  evento de salida. Un proceso que muere antes de inspeccionarse conserva una
  identidad desconocida. El total acumulado del Job se contrasta con los hechos
  registrados: discrepancias no permiten declarar inventario completo. Los
  eventos del Job son observaciones, no sustituyen la consulta de su contabilidad.
- Una identidad o pertenencia al Job realmente discrepante detiene la prueba.
  Un fallo de inspección raíz impide reanudar Chromium. Si falla la comprobación
  del Job, la limpieza también intenta terminar el handle de nuestra raíz suspendida.

[Opciones de Chrome headless](https://developer.chrome.com/docs/chromium/headless),
[herencia explícita de handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[información del Job](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject).

## Alcance del contenido y del informe

No existe entrada de URL, HTML, flags arbitrarios, proxy ni endpoint de depuración.
El único destino es un data URL construido desde una constante del código. El
HTML contiene un botón, un resultado pendiente y un script con nonce que hace un
click tras 50 ms virtuales y modifica el DOM. La CSP deniega conexiones y recursos
externos; el comando desactiva tareas de red de fondo y resolución de nombres.
Estas medidas NO verifican bloqueo de todo tráfico del sistema o de Chromium.
No se habilita navegación pública ni se desactiva el sandbox.

El perfil, TEMP/TMP, AppData y LocalAppData son nuevos, dentro del bundle. Chromium
recibe únicamente esas rutas y variables Windows seleccionadas, sin heredar API
keys, proxies ni el entorno completo del controlador. El ejecutable debe ser un
chrome.exe local ya existente en Program Files o, exclusivamente para este
diagnóstico, la ruta exacta del operador
`LOCALAPPDATA\ms-playwright\chromium-1208\chrome-win64\chrome.exe`.
LOCALAPPDATA debe ser una ruta Windows local, absoluta y canónica. No se admiten
otros usuarios, versiones, subdirectorios arbitrarios, rutas relativas, UNC,
streams alternativos ni componentes con puntos/espacios finales. Cambiar el
LOCALAPPDATA del operador invalida un bundle preparado para el anterior.
El lanzamiento sigue exigiendo un SHA-256 previamente aprobado y explícito.
Se mantiene abierto sin compartir escritura/borrado durante hash y lanzamiento.
Ese hash no acredita DLLs, recursos, procedencia del proveedor o aislamiento;
la instalación de Playwright en el perfil tampoco aporta esas garantías.

SHA-256 comunicado como dato observado por el operador:
`ff0c99fc5bb2301cad77930aa76e5354cf2a5fefb7efdcf3b3bc10ba0550c015`.
No constituye aprobación automática, no se usa como valor predeterminado y no se
incorpora como aprobación al preparar el bundle.

## Comparación controlada del entorno

`prepare --environment-mode minimal` conserva exactamente las ocho entradas del
diagnóstico anterior: SystemRoot, WINDIR, PATH, TEMP, TMP, USERPROFILE, APPDATA y
LOCALAPPDATA. Es el modo predeterminado y no consulta el entorno del padre para
construir el bloque del hijo.

`prepare --environment-mode windows_standard` conserva esas ocho entradas y
añade exclusivamente esta lista de candidatas estándar de Windows:

| Procedencia | Variables |
| --- | --- |
| Derivadas del directorio Windows obtenido por API y del perfil privado, o constantes | COMSPEC, SYSTEMDRIVE, OS, HOMEDRIVE, HOMEPATH, PATHEXT |
| Leídas individualmente del entorno del operador | PROGRAMDATA, ALLUSERSPROFILE, PROGRAMFILES, PROGRAMFILES(X86), PROGRAMW6432, COMMONPROGRAMFILES, COMMONPROGRAMFILES(X86), COMMONPROGRAMW6432, PROCESSOR_ARCHITECTURE, NUMBER_OF_PROCESSORS |

Las entradas opcionales ausentes se omiten; valores presentes malformados deniegan
el lanzamiento. Las rutas copiadas deben ser locales, absolutas y canónicas,
sin UNC, streams alternativos, controles ni componentes ambiguos. Arquitectura
y número de procesadores se validan. No se expanden variables ni se copia el
bloque del padre. API keys, secretos, proxies, PATH del operador y overrides de
Chromium quedan fuera de la lista. Los valores no se imprimen ni se guardan en
manifiestos, reservas o informes; solo se registra `environment_mode`.

Esta lista permite comprobar una hipótesis; todavía no se ha demostrado qué
entradas necesita este Chromium. TEMP, perfil, AppData y PATH siguen siendo
privados en ambos modos: esta comparación no descarta problemas comunes a esas
rutas ni reproduce todo el entorno habitual del operador. ProgramData y Program
Files pasan a ser rutas conocidas por Chromium, sin cambiar sus permisos ni
atribuirles aislamiento. Véase la documentación de Microsoft sobre
[bloques de entorno explícitos](https://learn.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables)
y [variables estándar](https://learn.microsoft.com/en-us/windows/deployment/usmt/usmt-recognized-environment-variables).

El modo queda fijado al preparar y no se puede sobreescribir en `run`. Cada
comparación exige dos bundles nuevos, cada uno con su reserva propia. Los bundles
antiguos sin `environment_mode` se rechazan: conservarlos como evidencia y no
editar sus manifiestos ni liberar sus reservas. El ejecutable, hash aprobado,
fixture, sandbox, Job, handles, límites, watchdog y flags de navegación son los
mismos; solo cambian el bloque elegido y las rutas nuevas de cada bundle.

El informe distingue:

- `dom_status`: missing, empty, oversized, invalid_encoding, unreadable,
  invalid_html, markers_missing o markers_observed. La fuente HTML por sí sola
  nunca demuestra ejecución. No se publica el DOM ni stderr en bruto.
- `wait_outcome`: salida observada, wall_timeout o proceso no iniciado. Un timeout
  conserva y analiza la salida parcial después del intento de terminación.
- `inspection_complete`: requiere que se reconcilie el inventario del Job y que
  TODAS las identidades y pertenencias observadas estén verificadas. Una identidad
  desconocida no impide conservar una observación funcional del DOM, pero impide
  declarar completa la inspección.
- `cleanup_verified`: solo confirma Job vacío, raíz detenida y handles cerrados
  según las llamadas nativas. No acredita borrado del perfil ni ausencia de todos
  los procesos del sistema. Un watchdog o consulta fallida no lo certifica.
- `status=synthetic_dom_observed`: requiere marcadores de DOM, raíz verificada,
  salida natural con código cero y limpieza confirmada, sin errores de ejecución.
  No significa que todas las inspecciones hayan tenido éxito ni concede seguridad.
- `repository_audit={status:not_performed, complete:false}`: no se usa el tamaño
  ni un prefijo del inventario del repositorio como resultado de seguridad.
  Las comprobaciones y bloqueos del camino de producción permanecen intactos.

Los directorios de trabajo se comprueban y mantienen abiertos sin compartir
borrado durante las escrituras del backend, rechazando reparse points. Esto no
constituye aislamiento frente a otros procesos con la misma identidad.

La lectura del DOM se limita a 64 KiB, stderr a 256 KiB y las observaciones a
128 procesos; el Job se configura para hasta 64 procesos activos. El backend
muestrea el tamaño de las salidas y detiene la prueba si exceden esos límites;
no es una cuota de disco y los archivos pueden crecer más antes del siguiente
muestreo. Excesos o errores detienen la prueba y conservan la evidencia.
Nunca se borra automáticamente el bundle, el perfil o su
reserva active-lease.json, incluso si terminó correctamente. Para repetir, crear
un bundle nuevo. No reutilizar ni liberar una reserva incierta.

## Procedimiento reproducible para el operador

1. Revisar estos archivos y ejecutar las regresiones desde E:\JARVIS. Esto no
   ejecuta Chromium; los arranques e inspecciones de hijos están simulados:

   ```powershell
   & 'E:\JARVIS\.venv\Scripts\python.exe' -m pytest -q tests\test_chromium_diagnostic.py tests\test_browser_run_environment.py tests\test_browser_chromium_sid_lab.py
   ```

2. Preparar únicamente fixtures y manifiestos en DOS bundles nuevos. No se accede
   al ejecutable, se solicita identidad ni se lanza el navegador. Usar el mismo
   Chromium ya existente en los dos. Para la ubicación exacta de Playwright:

   ```powershell
   Set-Location -LiteralPath 'E:\JARVIS'
   $PythonDiagnostico = 'E:\JARVIS\.venv\Scripts\python.exe'
   $ScriptDiagnostico = 'E:\JARVIS\tools\experimental\run_chromium_diagnostic.py'
   $ChromiumDiagnostico = Join-Path $env:LOCALAPPDATA 'ms-playwright\chromium-1208\chrome-win64\chrome.exe'
   $SalidaMinimal = & $PythonDiagnostico $ScriptDiagnostico prepare --chromium $ChromiumDiagnostico --environment-mode minimal
   if ($LASTEXITCODE -ne 0) { throw 'Preparación minimal denegada; revisar el resultado.' }
   $Minimal = $SalidaMinimal | ConvertFrom-Json
   $SalidaWindows = & $PythonDiagnostico $ScriptDiagnostico prepare --chromium $ChromiumDiagnostico --environment-mode windows_standard
   if ($LASTEXITCODE -ne 0) { throw 'Preparación windows_standard denegada; conservar ambos bundles.' }
   $Windows = $SalidaWindows | ConvertFrom-Json
   $Minimal
   $Windows
   ```

   Cada comando devuelve una ruta chromium-diagnostic-review-<id> distinta. Revisar
   ambos manifest.json y fixture.html: los manifiestos deben diferir únicamente
   en environment_mode y los fixtures deben ser idénticos. El manifiesto y el
   fixture se validan al ejecutar; modificaciones, campos duplicados, modo
   desconocido o presupuestos distintos bloquean. No instalar ni copiar binarios.

3. Antes de ejecutar, revisar las reservas e informes anteriores. Si alguna
   limpieza es incierta, detenerse hasta la recuperación manual del operador.
   Usar la misma sesión normal, equipo y binario aprobado para ambas pruebas,
   sin aplicaciones Chromium concurrentes relacionadas con el diagnóstico.
   Si cambia el binario o el entorno entre pruebas, la comparación pierde control.
   La ruta alternativa por defecto sigue siendo
   C:\Program Files\JARVISBrowserLab\chrome.exe; no reparar ACL, elevarse ni cambiar
   de identidad si no resulta accesible. Preparar otro par con --chromium si se
   elige un binario permitido diferente.

4. Solo cuando el operador decida realizar la prueba sintética, desde su sesión
   normal, sin credenciales ni cuenta restringida, proporcionar el hash aprobado:

   ```powershell
   $HashChromiumAprobado = '<sha256-previamente-revisada-de-64-caracteres>'
   if ($HashChromiumAprobado -cnotmatch '^[a-f0-9]{64}$') { throw 'Falta un SHA-256 aprobado explícitamente.' }
   & $PythonDiagnostico $ScriptDiagnostico run `
     --bundle $Minimal.bundle `
     --approved-chromium-sha256 $HashChromiumAprobado `
     --acknowledge-diagnostic-only
   $CodigoMinimal = $LASTEXITCODE
   $RutaInformeMinimal = Join-Path $Minimal.bundle 'report.json'
   if (-not (Test-Path -LiteralPath $RutaInformeMinimal -PathType Leaf)) { throw 'Falta informe; revisar watchdog/reserva antes de continuar.' }
   $InformeMinimal = Get-Content -LiteralPath $RutaInformeMinimal -Raw | ConvertFrom-Json
   if ($InformeMinimal.cleanup_verified -ne $true -or $InformeMinimal.environment_mode -ne 'minimal') { throw 'Limpieza o modo inciertos; revisión manual obligatoria.' }
   # Revisar el informe y la salida anterior, incluido $CodigoMinimal.
   # Un diagnóstico fallido con limpieza verificada sí puede compararse.
   & $PythonDiagnostico $ScriptDiagnostico run `
     --bundle $Windows.bundle `
     --approved-chromium-sha256 $HashChromiumAprobado `
     --acknowledge-diagnostic-only
   $CodigoWindows = $LASTEXITCODE
   ```

   Un hash observado no constituye aprobación implícita. No usar los lanzadores
   SID anteriores, runas, tareas registradas, contraseñas ni flags de sandbox como
   alternativa. Si el binario o la identidad no pasan, conservar el resultado y
   detenerse. El diagnóstico nunca activa el navegador de producción.

5. Revisar en cada bundle report.json o, si venció el watchdog, watchdog-report.json.
   Comparar environment_mode, status, wait_outcome, dom_status, exit_code,
   inspection_complete, cleanup_verified y stderr_categories. No volcar entornos,
   DOM, perfiles o stderr bruto a informes compartidos. Un éxito solo en
   windows_standard sería compatible con una contribución del grupo de variables
   añadido; requiere repetición con pares nuevos para descartar efectos de orden.
   Si ambos fallan, no se descarta todo el entorno personalizado, porque comparten
   las rutas privadas y PATH. Un crash del servicio de red es una observación,
   no prueba de su causa. La ausencia de Application 1000/1001 tampoco demuestra
   ausencia de fallos en hijos.
   Si la limpieza es incierta, no ejecutar otro bundle hasta revisar manualmente
   los procesos y handles correspondientes. No matar procesos ajenos por PID ni
   borrar rutas después de una comprobación previa de enlaces. No hay recuperación
   privilegiada ni borrado automático en este modo.

## Evidencia disponible y pendiente

El operador comunicó que su ejecución real anterior produjo wall_timeout, DOM
vacío y network_service_crash_reported; las identidades y pertenencia al Job de
los 10 procesos registrados estaban verificadas y no encontró Application
1000/1001 en el intervalo consultado. Esa evidencia no confirma la causa del
bloqueo. Esta revisión no repite Chromium ni consulta nuevos eventos Windows.

Las regresiones de esta comparación usan entornos centinela y arranques,
inspecciones, salidas y timeouts simulados. Solo la prueba de lectura del token
actual consulta Windows realmente. No se han solicitado credenciales ni ejecutado
pruebas con la cuenta restringida; tampoco se cambian ACL, firewall, políticas
ni instalaciones. La preparación escribe solamente datos de revisión.

Pendiente: ejecutar ambos modos bajo el operador normal con el mismo Chromium y
SHA-256 aprobados, contrastar tiempos/DOM reales y revisar cualquier hijo que
continúe inaccesible. No se ha probado qué variables necesita Chromium ni que
esta ampliación resuelva el bloqueo. La causa exacta histórica y las garantías
de sandbox, confinamiento de archivos o red siguen sin verificarse. Producción
permanece bloqueada y no se autoriza navegación pública.
