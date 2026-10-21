# Observación mínima de salidas de Chromium

Revisión: 18 de octubre de 2026. Solo auditoría, instrumentación, pruebas
simuladas y preparación. Chromium no se ha ejecutado en esta revisión.

## Auditoría del código previo

El supervisor ya tenía un IOCP asociado al Job antes de crear la raíz, snapshots
de sus PID, contabilidad final, verificación de token/pertenencia y contadores
de eventos. Solo conservaba el handle de la raíz. `inspect()` cerraba los handles
de los hijos y `ProcessLedger.exit(pid)` marcaba la entrada actual de ese PID.
No guardaba tipo, estado de salida ni tiempo de observación de los hijos.

Por tanto, esos datos no bastaban para identificar el proceso histórico que
terminó junto a `network_service_crash_reported`. Ni el token del operador ni un
PID son una identidad de instancia. Los eventos EXIT/ABNORMAL_EXIT llevan PID,
no un handle, generación, instante de salida o código DWORD completo.
Microsoft advierte expresamente sobre reutilización de PID y entrega no
garantizada de estas notificaciones:
[JOBOBJECT_ASSOCIATE_COMPLETION_PORT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port).

Se reutilizan el IOCP, los snapshots, las verificaciones y la contabilidad;
no se añade otro recolector, WMI, ETW, depurador, volcado o endpoint CDP.

## Instrumentación

NEW y los snapshots descubren candidatos. Se abre cada candidato con
`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` (`0x101000`), no heredable.
En el mismo handle se consulta la creación mediante `GetProcessTimes`, el token
y `IsProcessInJob` respecto al supervisor exacto. Solo esa combinación permite
publicar evidencia del proceso. Los handles se conservan, con el límite previo
de 128 instancias, y se cierran en la limpieza existente. La raíz conserva el
handle devuelto por `CreateProcessW`.

PID y creación distinguen generaciones dentro del inventario en memoria; el
handle fija el objeto de proceso durante la observación. Una notificación de
salida solo aumenta su contador: nunca marca una entrada por PID. Los handles
siguen siendo válidos tras la salida:
[Process Handles and Identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers),
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).

Para conocer el tipo declarado se comprueba en memoria la imagen frente a la
ruta del Chromium fijado y se intenta una consulta nativa de clase 60,
`ProcessCommandLineInformation`, sobre ese mismo handle. Se usa un único buffer
de 64 KiB, se comprueban tamaño, longitud y que el puntero UNICODE_STRING quede
dentro de la respuesta. `CommandLineToArgvW` separa los argumentos y una lista
cerrada reduce `--type` y `--utility-sub-type` a una categoría. Solo
`utility` con `network.mojom.NetworkService` produce `network-service`.
Ausencia, duplicados, denegación, imagen distinta o respuesta inválida producen
`unknown`. No se amplían derechos ni se recorre el PEB como alternativa.

La clase 60 es una interfaz interna, no una garantía pública de compatibilidad
de Microsoft. Su definición se contrasta con los
[headers de System Informer](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h).
Microsoft avisa de cambios posibles en
[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
Si no está disponible, el tipo permanece desconocido. La categoría describe
argumentos declarados; no demuestra que ese servicio llegara a inicializarse.

La línea y los argumentos existen transitoriamente en memoria para esa
reducción. No se escriben, imprimen ni incorporan a excepciones o informes.
El buffer nativo se pone a cero y el argv se libera. Esto no garantiza borrar
todas las copias temporales de strings que gestionan Python y Windows.

El esquema 2 exporta por instancia exclusivamente:

| Campo | Significado |
| --- | --- |
| `process_type` | `browser`, `renderer`, `gpu-process`, `utility`, `network-service`, `crashpad-handler` o `unknown` |
| `membership` | `verified` solo tras verificar instancia, token y pertenencia al supervisor; en otro caso `unknown` |
| `exit_code` | DWORD sin interpretar, o `null` si no se pudo consultar |
| `exit_observed_ms` | Milisegundos monotónicos desde el inicio del backend hasta observar el handle señalado, o `null` |
| `exit_phase` | `before_cleanup`, `cleanup_window` o `unknown` |

No exporta PID, creación absoluta, token, SID, imagen, línea de comandos,
argumentos, rutas de perfiles, valores de entorno ni detalles privados del hijo.
El resto del informe conserva las observaciones técnicas previas del Job y de
la prueba sintética. No se añade ningún archivo de telemetría bruto. El bundle
nuevo usa `logging_mode=disabled`; no activa el log verbose de Chromium.

Se llama a `GetExitCodeProcess` únicamente después de que `WaitForSingleObject`
confirme la señal del handle. Así, 259 puede ser una salida real y no se confunde
con STILL_ACTIVE. Una consulta denegada deja el código en `null`.
La salida se observa aunque no llegue un paquete EXIT del Job.

Antes del primer intento de terminar supervisor, guardia o raíz se consultan
los handles. Esas salidas son `before_cleanup`. Desde esa frontera toda nueva
salida observada es `cleanup_window`, aunque se reciba un paquete antiguo.
No se convierte código 100 en una prueba causal: es el valor solicitado por
la limpieza existente, pero también podría haberlo usado otro actor.

`exit_observed_ms` es un instante de observación y un límite superior del momento
real de salida, no un timestamp exacto del kernel. El sondeo normal espera hasta
25 ms entre ciclos, pero las consultas y la planificación añaden demora; no se
promete esa precisión. Una salida entre el último sondeo y el primer intento de
terminación queda conservadoramente en `cleanup_window`.

## Completitud e interpretación

`process_inventory_complete` exige contabilidad final reconciliada con las
instancias únicas verificadas y ausencia de huecos de observación.
`inspection_complete` conserva su condición explícita de verificación.
`exit_observation_complete` solo es true si además todas las instancias tienen
tipo conocido, salida observada y código disponible. Campos insuficientes
mantienen estos indicadores en false y nunca se rellenan por inferencia.
`events_complete` sigue siendo false: la entrega completa de paquetes no está
garantizada. Un proceso que nace y muere antes de obtener su handle puede
quedar sin identificar; la contabilidad o un fallo de apertura impiden certificar
el inventario. Los contadores de salida no se vinculan a una instancia por PID.

El estado funcional `synthetic_dom_observed` sigue describiendo solo DOM,
salida de la raíz y limpieza; no certifica la telemetría de hijos. La ausencia
de datos de un hijo no concede aislamiento ni permiso de producción.

El siguiente diagnóstico podría mostrar que una instancia declarada
`network-service`, verificada en el supervisor, terminó antes de nuestra
limpieza, con un código y una posición temporal concretos. También podría
mostrar que salió otro tipo de hijo, varias instancias de red, o únicamente
salidas observadas durante limpieza. No sería legítimo identificar la instancia
histórica a partir de estos datos nuevos ni vincular automáticamente un mensaje
`network_service_crash_reported` concreto a una fila: no se añade una cronología
de mensajes de Chromium.

El código puede orientar una hipótesis de excepción o fallo de inicialización,
pero por sí solo no prueba quién terminó el proceso, la instrucción o DLL
responsable, una denegación concreta, un fallo del sandbox, una cuota interna,
interferencia de seguridad, ni el origen del timeout. Un proceso puede devolver
un código voluntariamente o recibirlo en `TerminateProcess`; una excepción fatal
también puede convertirse en código:
[Terminating a Process](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process).
Tampoco la falta de salidas observadas descarta un fallo temprano inaccesible.

## Bundle preparado y controles conservados

Bundle nuevo, sin ejecutar:
[ecdedbd3e0dc4631804894b1b2adb2a8](../../../chromium-diagnostic-review-ecdedbd3e0dc4631804894b1b2adb2a8/manifest.json).
Contiene solo `manifest.json` y `fixture.html`, esquema 2, `minimal`, `job_list`,
logging desactivado. No tiene sesión, reserva, informe ni hash aprobado.
Los manifiestos v1 se rechazan sin migrarlos; los experimentos anteriores se
conservan intactos y no se vuelven a ejecutar.

Se conservan supervisor, guardia cuando corresponde, sandbox sin bypass,
límites `0x2008`/64 procesos, verificación antes de reanudar, fijación/hash del
ejecutable, rechazo de reparse points, herencia exclusiva de stdio, navegación
sintética, plazos 30/6 s y watchdog 46 s. El wrapper CLI no cambia. Producción
permanece bloqueada. No se modifican ACL, firewall, cuentas ni políticas y no
se hacen commits.

## Pruebas

```powershell
& 'E:\JARVIS\.venv\Scripts\python.exe' -m pytest -q tests\test_chromium_diagnostic.py -k 'not real_current_token'
```

Las consultas nuevas de procesos, tiempos, imagen, argv y salidas están
simuladas. Se excluye la lectura real del token actual. Se cubren generaciones,
paquetes atrasados, handles señalados sin notificación, código 259, accesos
denegados, buffers nativos inválidos, redacción, esquemas anteriores, frontera
de limpieza, cierre de handles y conservación de los controles existentes.

Resultado: **99 pruebas y 362 subpruebas correctas; 1 prueba excluida**.
