# Job supervisor y sandbox de Chromium en Windows 11

Revisión: 17 de octubre de 2026. Investigación documental y pruebas simuladas;
no se ha ejecutado Chromium. El `wall_timeout` de 30 s, el DOM vacío y
`network_service_crash_reported` en ambos entornos no identifican la causa.
Pertenencia e identidad verificadas, Job vacío y limpieza completa acreditan
esas comprobaciones; no acreditan que Chromium haya inicializado su sandbox.

## Restricciones documentadas y posibles conflictos

Microsoft admite jobs anidados desde Windows 8. La jerarquía requiere conjuntos
de procesos compatibles y orden de asociación de padre a hijo; las restricciones
de UI condicionan el anidamiento. Algunos límites efectivos se toman del más
restrictivo de la cadena. La contabilidad del padre incluye sus jobs hijos.
Por tanto, prohibir breakaway no equivale por sí solo a prohibir todos los jobs
internos de una aplicación en Windows 11.
[Microsoft: Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).

`AssignProcessToJobObject` necesita derechos de asignación en el Job y
`PROCESS_SET_QUOTA | PROCESS_TERMINATE` en el proceso. Si este ya pertenece a un
Job, el destino debe estar vacío o en una jerarquía compatible y sin límites
de UI. Un Job terminándose, una cuota agotada o una jerarquía inválida puede
rechazar la operación. Los handles raíz de `CreateProcessW` se conservan para
la asociación; nunca se abre un PID ajeno con esos derechos.
[Microsoft: AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).

El código Chromium consultado en `main` mantiene jobs propios: `Job::Init`
siempre configura `KILL_ON_JOB_CLOSE`; según nivel puede añadir UI, un proceso
activo, `DIE_ON_UNHANDLED_EXCEPTION` y memoria por proceso. Esto describe
posibilidades de las políticas, no los límites observados del binario local.
No se cambian ni eliminan estas políticas.
[Chromium: job.cc](https://github.com/chromium/chromium/blob/main/sandbox/win/src/job.cc).

El broker actual crea el target suspendido y añade su Job a los atributos de
creación. `StartupInformationHelper` usa `PROC_THREAD_ATTRIBUTE_JOB_LIST`.
El atributo no es intrínsecamente ajeno al sandbox de Chromium. Las referencias
`main` son móviles y no están vinculadas por evidencia al hash del ejecutable
local: no prueban compatibilidad universal de todas sus políticas de UI.
[Chromium: broker_services.cc](https://github.com/chromium/chromium/blob/main/sandbox/win/src/broker_services.cc),
[Chromium: startup_information_helper.cc](https://github.com/chromium/chromium/blob/main/sandbox/win/src/startup_information_helper.cc).

La política Chromium también contempla un Job de vida útil para determinados
procesos de red incluso en su camino interno sin sandbox. El mensaje de crash
del servicio de red no distingue entre fallo de asociación, límites, permisos,
DLLs o inicialización de otros componentes. No justifica cambiar el sandbox.
[Chromium: sandbox_win.cc](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc).

## Configuración exacta de JARVIS

| Elemento | Valor efectivo solicitado y verificado |
| --- | --- |
| Creación del Job | `CreateJobObjectW(NULL, NULL)`: anónimo, handle no heredable |
| `JobObjectExtendedLimitInformation` | `LimitFlags=0x2008` |
| `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | `0x2000` |
| `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` | `0x0008`, `ActiveProcessLimit=64` |
| UI | `JobObjectBasicUIRestrictions=0`, leído de vuelta |
| Breakaway | No se fijan `0x0800` ni `0x1000` |
| Memoria, tiempo de CPU, working set, afinidad, prioridad, scheduling | Sin flags de activación; no se configura CPU rate |
| Creación del proceso | `0x08080404 = CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED` |
| Atributos | `HANDLE_LIST=0x20002`, solo stdin/stdout/stderr; `JOB_LIST=0x2000d` |
| Puertos de eventos | Un IOCP, clave 1 supervisor, clave 2 guardia; asociados antes de crear procesos |
| Plazos externos | 30 s reales; 6 s limpieza; watchdog 46 s. No son cuotas CPU del Job |

La guardia usa exactamente los mismos límites. Las consultas de vuelta verifican
flags exactos, 64 procesos y UI cero antes de crear el navegador. Campos sin
flag pueden devolver defaults de Windows, por ejemplo SchedulingClass=5; no
se interpretan como límites activos. El máximo de 128 observaciones acumuladas,
DOM de 64 KiB y stderr de 256 KiB son presupuestos del diagnóstico, no cuotas
de memoria o disco del Job.

El límite activo podría impedir un lanzamiento si se alcanza; no se elimina
para comparar. `KILL_ON_JOB_CLOSE` actúa al cerrar el último handle, por lo que
los handles del Job quedan exclusivamente en el worker y fuera de HANDLE_LIST.
La falta de flags de memoria/CPU propios no descarta límites ambientales o de
Chromium. Las reglas de activación de límites y la terminación al exceder el
número activo están documentadas por
[Microsoft: JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).

Se consulta si el worker ya está en un Job y, de ser así, sus límites inmediatos.
Una consulta fallida o UI ambiental no cero impide lanzar. No se enumeran handles
del sistema ni se afirma conocer toda la cadena ambiental. Tampoco se inspeccionan
directamente los handles de jobs internos de Chromium. No se habilita breakaway:
si algún componente lo necesita y Windows rechaza su creación, se conserva el
fallo en lugar de permitir descendientes fuera de la contención.

## Comparación preparada

| `job_launch_mode` | JOB_LIST al crear, siempre suspendido | Antes de reanudar | Contención desde creación |
| --- | --- | --- | --- |
| `job_list` | `[supervisor]` | Identidad y pertenencia raíz | Supervisor |
| `guarded_job_list` | `[guardia, supervisor]` | Guardia, identidad y pertenencia raíz | Guardia y supervisor |
| `guarded_assign` | `[guardia]` | Guardia; ausencia inicial en supervisor; `AssignProcessToJobObject`; identidad y pertenencia raíz | Guardia; después también supervisor |

`guarded_job_list` frente a `guarded_assign` conserva la misma jerarquía final
guardia → supervisor → jobs internos que pueda crear Chromium. Cambia el momento
y API de asociación del supervisor. El baseline `job_list` permite detectar si
añadir una guardia ya altera el resultado. Comparar solo baseline y asignación
explícita confundiría el método con el nivel adicional de jerarquía.

Microsoft documenta que JOB_LIST asigna los handles en el orden indicado y está
disponible desde Windows 10. Los buffers de atributos se mantienen vivos hasta
destruir la lista.
[Microsoft: UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

No existe alternativa de crear una raíz suspendida sin Job protector y asignarla
después: la muerte del worker entre ambas operaciones dejaría una raíz sin el
cierre por Job. En el método explícito la guardia ya está asociada atómicamente
en `CreateProcessW`, incluso antes de que este devuelva sus handles. Si falla la
asociación del supervisor, jamás se llama a ResumeThread. La suspensión por sí
sola no se considera contención.

Ante un fallo se intenta terminar supervisor y guardia, y el handle raíz propio
si sigue vivo. Se consulta la contabilidad de ambos, se espera la salida raíz
y se cierran todos los handles. Solo Job(s) vacíos, raíz detenida y cierres
correctos permiten `cleanup_verified=true`. Si el worker desaparece, el cierre
de sus handles activa KILL_ON_JOB_CLOSE; el padre registra reserva incierta y
`cleanup_verified=false`, sin certificar un vaciado que no ha observado.

## Observaciones nuevas sin contenido sensible

`job_diagnostics` registra método, flags de creación, etapas con resultado y
código Win32, límites leídos, pertenencia ambiental categórica, contadores de
eventos separados por clave, máximo activo **muestreado** y contabilidad final
numérica (`active`, `total`, `terminated`) de cada Job. No incorpora entornos,
usuarios, SID, nombres de jobs, handles, líneas de comando, DOM o stderr brutos.
Los PIDs ya existentes se mantienen exclusivamente en el inventario acotado.

`event_scope=associated_job_or_descendants`: un evento recibido por el puerto
del supervisor puede proceder de un Job interno. No permite atribuir su cuota
al supervisor. Los eventos de la guardia no alimentan otra vez el inventario.
Durante limpieza se siguen drenando notificaciones tras un evento de límite
para reconciliar salidas e inventario; el error se conserva.

Las notificaciones ordinarias no tienen entrega garantizada. La ausencia de
`active_process_limit` no demuestra que nunca ocurrió, y `active_process_zero`
no sustituye la contabilidad. `events_complete` permanece false. La validación
también exige la secuencia de contención antes de reanudar en informes de
timeout o crash, aunque no haya éxito funcional.
[Microsoft: JOBOBJECT_ASSOCIATE_COMPLETION_PORT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port).

## Procedimiento con bundles nuevos

1. Ejecutar únicamente las regresiones simuladas indicadas al final. Conservar
   los bundles previos y sus reservas. Los manifiestos sin `job_launch_mode` se
   rechazan; no actualizarlos ni reutilizarlos.
2. Preparar tres bundles nuevos bajo el mismo entorno fijo. Estos comandos
   escriben datos y no leen ni ejecutan el binario. La ruta Playwright sigue
   limitada a la ubicación exacta ya admitida por este diagnóstico:

   ```powershell
   Set-Location -LiteralPath 'E:\JARVIS'
   $PythonDiagnostico = 'E:\JARVIS\.venv\Scripts\python.exe'
   $ScriptDiagnostico = 'E:\JARVIS\tools\experimental\run_chromium_diagnostic.py'
   $ChromiumDiagnostico = Join-Path $env:LOCALAPPDATA 'ms-playwright\chromium-1208\chrome-win64\chrome.exe'
   $BundlesJobs = @{}
   foreach ($MetodoJob in @('job_list','guarded_job_list','guarded_assign')) {
       $PreparadoJob = & $PythonDiagnostico $ScriptDiagnostico prepare --chromium $ChromiumDiagnostico --environment-mode minimal --job-launch-mode $MetodoJob
       if ($LASTEXITCODE -ne 0) { throw 'Preparación denegada; conservar los bundles ya creados.' }
       $BundlesJobs[$MetodoJob] = $PreparadoJob | ConvertFrom-Json
   }
   $BundlesJobs.Values
   ```

3. Revisar que las tres rutas difieren, los fixtures son idénticos y los
   manifiestos solo difieren en `job_launch_mode`. Mantener máquina, operador
   estándar, binario/hash revisado, entorno y presupuestos iguales. Perfiles y
   directorios de cada sesión son independientes. Si se quiere repetir con
   `windows_standard`, preparar otro triplete; no mezclar las variables.
4. La ejecución queda **fuera de esta tarea**. Para una prueba futura revisada,
   usar el CLI `run` con `--bundle <ruta-nueva>`,
   `--approved-chromium-sha256 <hash-revisado>` y
   `--acknowledge-diagnostic-only`, un bundle cada vez. Revisar su report.json,
   código de salida, etapas y limpieza antes del siguiente. Un watchdog, ausencia
   de informe o limpieza incierta obliga a revisión manual, sin liberar reservas.
5. Comparar `wait_outcome`, `dom_status`, `exit_code`, `stderr_categories`,
   `inspection_complete`, `cleanup_verified` y `job_diagnostics`. Revisar primero
   errores de creación/asociación y flags realmente leídos, después eventos y
   contabilidad. No compartir archivos de perfil, entornos o salidas brutas.

| Resultado futuro | Interpretación admisible |
| --- | --- |
| Baseline y ambos guarded fallan igual | El método no discrimina; quedan causas comunes, límites internos/ambientales y otras inicializaciones |
| Solo ambos guarded fallan | Compatible con influencia de la guardia/jerarquía adicional |
| Los dos guarded difieren | Compatible con influencia del método/momento de asociación; repetir invirtiendo orden con otro triplete |
| Falla una API antes de ResumeThread | Fallo de preparación/asociación; no se ejecutó código del navegador |
| Hay evento de límite | Se observó una cuota en ese Job o descendientes; no atribuirla automáticamente al supervisor |

Una diferencia es evidencia de asociación, no prueba causal definitiva. Si se
mantiene la misma firma de fallo no se puede prometer resolverla con un cambio
de API. No hay comparación sin Job ni cambio de sus límites de contención.

Triplete preparado durante esta revisión, en `minimal`, todavía sin ejecutar:

| Método | Manifiesto nuevo |
| --- | --- |
| `job_list` | [5b9f6184d56e45129ea2c0333952eba3](../../../chromium-diagnostic-review-5b9f6184d56e45129ea2c0333952eba3/manifest.json) |
| `guarded_job_list` | [6271f688180d4cb2b06571d2239c7fb5](../../../chromium-diagnostic-review-6271f688180d4cb2b06571d2239c7fb5/manifest.json) |
| `guarded_assign` | [3eea3f5456664ee3a740c5197be4291f](../../../chromium-diagnostic-review-3eea3f5456664ee3a740c5197be4291f/manifest.json) |

Solo contienen fixture y manifiesto. No tienen sesión, reserva ni hash aprobado.

## Verificación realizada

```powershell
& 'E:\JARVIS\.venv\Scripts\python.exe' -m pytest -q tests\test_chromium_diagnostic.py tests\test_browser_run_environment.py tests\test_browser_chromium_sid_lab.py
```

Resultado: **106 pruebas y 347 subpruebas correctas**.

Las pruebas cubren ambos entornos y los tres métodos; fallos Win32 de creación,
límites, consulta, asociación y reanudación; guardia todavía activa, contabilidad
inaccesible, terminación/cierre fallidos, watchdog, orden de verificación,
eventos propagados, cuotas, cotas de lectura y reserva independiente. Todas las
operaciones de lanzamiento/cierre de navegador están simuladas. En la suite del
diagnóstico solo la prueba ya existente del token actual hace esa lectura real;
las regresiones asociadas también leen descriptores de seguridad y verifican
helpers PowerShell en memoria, sin instalar ni cambiar ACL. No se afirma haber probado
el cierre por caída del worker en el kernel real ni jobs internos del binario.

Se conservan HTML y CSP, identidad estándar, hash y fijación del ejecutable,
rechazo de reparse points, presupuesto de tiempo, handles explícitos, ausencia
de navegación pública y bypass de sandbox, y bloqueo de producción. No se
cambian firewall, políticas, ACL ni otros experimentos; no se hacen commits.
