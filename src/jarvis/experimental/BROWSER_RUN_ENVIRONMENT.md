# Entorno de ejecución en ProgramData: revisión y recuperación manual

Esta implementación mantiene `trusted/control/sessions`, una única reserva
persistente por SID, la identidad del worker y el comportamiento fail-closed.
No instala ni repara permisos desde el controlador. El instalador crea únicamente
un espacio NUEVO; requiere aprobación explícita y una consola ya elevada.

**Estado: preparado para revisión, lanzamiento bloqueado.** Las ACL no garantizan
que un worker con permiso para crear archivos no pueda ejecutarlos posteriormente.
El código termina con `session_execution_confinement_not_verified` aun cuando
pasen todas las comprobaciones previas. No hay opción para omitir este bloqueo.
Instalar el entorno no autoriza Chromium ni acredita aislamiento completo.

## Separación y ACL

El espacio fijo es `C:\ProgramData\JARVISBrowserLab`:

- `trusted`: helper, SHA256 aprobado y manifiesto final; propietario
  Administrators. SYSTEM/Administrators tienen control completo; worker y
  controlador solo lectura/ejecución. Los archivos usan ACEs sin herencia.
- `control`: resultados y reserva `active-lease.json`; worker sin acceso.
- `sessions`: controlador puede crear hojas; worker solo puede atravesar.
- `sessions\<32-hex-id>`: hoja nueva, propietario controlador, DACL
  protegida. Worker puede leer/escribir/borrar, sin ejecución de archivos ni
  modificación de DACL/propietario. Denegaciones explícitas heredables al SID y
  a OWNER RIGHTS cubren también grupos e implicitamente el propietario.

Tras aplicar la DACL de la hoja se releen propietario, protección, orden, máscaras
y flags de TODAS las ACEs. Un éxito de Set-Acl no basta. Cualquier error conserva
la reserva, sin reparar permisos ni tocar hojas anteriores.

Las denegaciones heredables son defensa adicional para objetos que las heredan.
Un creador puede proporcionar una DACL protegida propia; por ello no se afirma
que esas denegaciones impidan ejecutar todo archivo futuro. Haría falta una
política de ejecución de Windows independiente, revisada y verificada con el
worker, antes de implementar y aprobar una vía de lanzamiento. No se configura
esa política ni se incorpora un bypass en esta revisión.
[Modelo de seguridad e herencia de archivos de Windows](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

Un mismo SID accede a los mismos datos: ninguna DACL separa dos sesiones
simultáneas de ese SID. Cualquier hoja adicional o reserva anterior bloquea.
Procesos de ese SID fuera del Job también pueden afectar su sesión.

## Auditoría de acceso y coste

Medición de solo lectura en E:\JARVIS el 14 de octubre de 2026: 51.533 archivos y
5.855 directorios. Una enumeración scandir/lstat sin seguir reparse points tardó
0,187 s. El recorrido anterior, que repetía stat/is_symlink de cada ancestro,
comprobó 37.695 entradas en 10,016 s y se interrumpió para medir su coste.
Estos tiempos NO incluyen ACL, acceso efectivo, credenciales o aperturas nativas.
El timeout anterior de 20 s solo cubría el helper después de la enumeración;
el estado medido ya excedía su límite de 50.000 archivos.

La nueva auditoría:

- Recorre cada archivo Y directorio por scandir, incluyendo directorios vacíos,
  .git y artefactos. No selecciona una muestra ni confía solo en una raíz.
- Lee descriptores por handles locales NTFS con READ_CONTROL y OPEN_REPARSE_POINT.
  Rechaza reparse points, discrepancias de ruta final, descriptores incompletos,
  ACEs no soportadas y errores de enumeración. Mantiene abiertos los directorios
  visitados sin FILE_SHARE_DELETE durante la visita de sus descendientes.
- Usa LogonUser/DuplicateToken y AccessCheck(MAXIMUM_ALLOWED) con el token real,
  incluidos sus grupos y derechos de propietario. Rechaza SID incorrecto,
  pertenencia Administrators incluso deny-only y privilegios que permitan
  eludir controles, también si están deshabilitados pero presentes.
- Comprueba bits individuales de lectura/listado, escritura, creación de
  archivos/subdirectorios, atributos/EA, DELETE, DELETE_CHILD, WRITE_DAC y
  WRITE_OWNER. Audita los padres: DELETE_CHILD puede permitir borrar o renombrar
  una entrada aunque su DACL deniegue DELETE.
- Verifica lectura/escritura de la sesión, denegación de ejecución en el archivo
  de prueba existente, y ausencia de mutación en trusted, control y el
  repositorio. Cualquier otra sesión impide continuar.
- Reutiliza resultados solo para descriptores binarios idénticos dentro del mismo
  token/auditoría. La caché se vacía al cerrar el token; no sustituye la lectura
  de la ACL de ningún objeto.
- Conserva un máximo de 50.000 entradas, contando ahora también directorios,
  y un presupuesto cooperativo de 120 s desde el inicio de la comprobación.
  Exceder cualquiera deniega; no se acepta un prefijo recorrido. Una llamada
  Win32 síncrona puede tardar más que el presupuesto; al retornar se deniega.
- El helper anterior recibe solo UNA ruta del repositorio y confirma las
  aperturas de sus binarios y del archivo de prueba. Su campo
  repository_denial_verified es evidencia de esa ruta, no del repositorio entero.
  Su timeout es como máximo 20 s y nunca mayor que el presupuesto restante.

[Contrato de AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
La evaluación DACL es conservadora: no acredita todos los controles Windows,
políticas de ejecución, acceso a otros discos o confinamiento global. Tampoco
congela cambios concurrentes de contenido/ACL por otros principales autorizados.
No se han medido ni certificado las nuevas comprobaciones con la cuenta worker.
Con el inventario actual, el límite de entradas basta para denegar el lanzamiento;
esta revisión no lo eleva ni excluye directorios para aparentar una auditoría completa.

## Limpieza

finish_session devuelve False siempre, incluso con Job vacío, handles cerrados
e inspección completa. No recorre, resuelve, borra ni libera la reserva.

Comprobar enlaces antes de shutil.rmtree deja una carrera de sustitución por un
proceso del mismo SID, incluso fuera del Job. No hay aquí un borrado basado en
handles que pueda garantizar la identidad de cada objeto. Se conservan los
datos y la reserva para recuperación manual. No usar Remove-Item -Recurse,
shutil.rmtree, takeown ni icacls como reparación automática.
[Limitaciones documentadas de rmtree](https://docs.python.org/3.11/library/shutil.html#shutil.rmtree).

## Instalación revisada, todavía no autorizada ni ejecutada

Revisar fuente, helper y SHA256 previamente aprobado. No convertir un hash recién
calculado en aprobación implícita. El helper nativo anterior no cambia por esta
revisión; compilarlo de nuevo exige revisar y aprobar el nuevo artefacto.

El instalador exige -OperatorApproved, rechaza cualquier espacio existente y
no se autoeleva. CreateDirectory nativo falla atómicamente si alguien crea la
ruta entre la comprobación y la creación. Cada archivo usa CreateNew y recibe
propietario/DACL en su creación. La fuente se mantiene abierta sin compartir
escritura/borrado desde el cálculo del hash hasta la copia. Se comprueban ACL,
flags, propietario y hash antes del marcador final trusted\installation.json.

El manifiesto debe tener exactamente schema=1, state=staged, helper_sha256 y
controller_sid aprobados. Ausencia, truncamiento, campos duplicados, esquema
incorrecto o discrepancias bloquean verify_installed. Instalaciones anteriores
sin este manifiesto se conservan y requieren revisión independiente. El marcador
indica staging terminado; no es un certificado de acceso efectivo o no-ejecución.

Solo tras autorización del operador, en una consola elevada:

```powershell
# Definir estos valores a partir de la revisión aprobada, sin aprobación implícita.
$HelperRevisado = 'E:\JARVIS\<artefacto-revisado>\launcher.exe'
$Sha256Aprobado = '<64-caracteres-hex-aprobados>'

& 'E:\JARVIS\tools\experimental\Install-BrowserRunEnvironment-REVIEW.ps1' `
  -HelperPath $HelperRevisado `
  -ApprovedHelperSha256 $Sha256Aprobado `
  -ControllerSid 'S-1-5-21-2213057978-1848420950-3946800094-1001' `
  -OperatorApproved
```

La comprobación posterior sin creación de sesión ni cambio de ACL es:

```powershell
& 'E:\JARVIS\.venv\Scripts\python.exe' 'E:\JARVIS\tools\experimental\run_sid_chromium_review.py' check
```

check solo valida el staging; su mensaje no certifica acceso efectivo del worker.
run aplica únicamente la DACL no privilegiada de su hoja nueva, solicita una
contraseña transitoria y termina denegando el lanzamiento. Deja la hoja y la
reserva. No utilizar run para validar una instalación parcial ni repetirlo para
intentar superar errores. No se añaden navegación pública, --no-sandbox,
registro de tareas, Playwright ni cambios en cuentas/firewall/AppContainer.

## Procedimiento explícito ante instalación parcial o reserva pendiente

1. Detener nuevos intentos y conservar el error de etapa del instalador. No
   ejecutar de nuevo el instalador sobre la ruta existente ni fabricar el
   manifiesto final. Preservar también la reserva, perfiles y resultados; no
   exportar contraseñas, contenido de perfiles ni comandos sensibles.
2. Revisar en modo lectura la identidad del operador, los ancestros y los objetos
   existentes en la ruta fija. Enumerar un nivel cada vez, verificar enlaces y
   reparse points antes de descender; no hacer un borrado o inventario recursivo
   que los siga. Registrar rutas absolutas, volumen/identidad de objetos,
   propietario, DACL/flags, hash aprobado y presencia/contenido del manifiesto.
   Compararlos con los contratos de este documento y del código. Si falta acceso
   o alguna identidad es ambigua, detenerse; no otorgar acceso para continuar.
3. Correlacionar la reserva con la hoja exacta y comprobar TODOS los procesos con
   el SID worker, no solo los observados dentro del Job. Si no puede verificarse
   el token de un proceso, o quedan handles/actividad desconocidos, la recuperación
   sigue pendiente. Cerrar sesiones o detener procesos requiere una autorización
   independiente del operador; no se realiza desde este código.
4. Elegir explícitamente entre conservar el espacio bloqueado o autorizar una
   recuperación concreta. La autorización debe identificar los objetos y acciones
   exactos. La autorización de instalar un espacio nuevo no autoriza borrar uno
   anterior, tomar posesión, cambiar ACL, elevar permisos ni reparar archivos.
   No tocar E:\JARVIS-opencode ni experimentos AppContainer anteriores.
5. Cualquier retirada autorizada debe usar un procedimiento independiente
   revisado que garantice identidad/contención de cada objeto durante la operación,
   o realizarse en mantenimiento sin procesos/handles que puedan crear carreras.
   Rechazar enlaces/rutas ambiguas y conservar todo si no existe esa garantía.
   No ejecutar Remove-Item -Recurse tras una mera comprobación previa. No mover o
   borrar por rutas calculadas cuyo destino absoluto no se haya verificado.
6. En una sesión recuperada, confirmar primero la ausencia de datos y procesos
   residuales; liberar la reserva coincidente ÚLTIMO y solo con autorización.
   Una reserva sola también exige reconciliar el fallo que la creó. En una
   instalación parcial, confirmar la retirada autorizada de todo el espacio antes
   de aprobar una instalación NUEVA. No completar in situ un espacio incompleto
   ni debilitar sus ACL para que el verificador pase.

Si cualquiera de estos pasos no puede verificarse, se conserva la instalación o
reserva y se deniega el lanzamiento. La reparación privilegiada nunca es automática.

## Pruebas y alcance de la evidencia


```powershell
& 'E:\JARVIS\.venv\Scripts\python.exe' -m pytest -q tests\test_browser_run_environment.py tests\test_browser_chromium_sid_lab.py tests\test_browser_runtime_preparation.py tests\test_browser_sid_firewall_lab.py
```

Las pruebas de SID, ACL, creación, helper y lanzamiento usan mocks/descriptores
sintéticos. Las pruebas PowerShell solo analizan el AST y ejecutan funciones
seleccionadas con datos y creación simulados; no dot-source ni ejecutan el
instalador. Cubren permisos parciales, creación/borrado/renombrado por el padre,
límites, errores, propietario/herencia/denegaciones, otra sesión, reserva
incorrecta, instalación incompleta y carreras de limpieza/creación.

Se ha comprobado en Windows la lectura nativa, sin cambios, de tres descriptores
existentes con la cuenta del controlador. Las pruebas automatizadas también leen
un descriptor y usan el token REAL del controlador con descriptores exclusivamente
en memoria para comprobar AccessCheck, denegación, OWNER RIGHTS, caché y el caso
de una DACL protegida que permite ejecutar. El C# del instalador se compila para
validar sintaxis, sin invocar la creación nativa. Los errores de identidad,
pertenencia admin deny-only y privilegios deshabilitados usan buffers simulados.
Esto no verifica acceso efectivo ni no-ejecución con jarvis_browser_lab. La
instalación, LogonUser del worker, creación/renombrado reales bajo ese SID,
Chromium y una política de ejecución independiente siguen sin verificarse.
