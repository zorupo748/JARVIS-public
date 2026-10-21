"""Opt-in synthetic Chromium diagnosis, independent of production authorization.

No credentials, URL input, policy/ACL changes or production/browser integration.
The operator identity is inherited explicitly; the restricted SID is refused.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from html.parser import HTMLParser
import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import time
import uuid

WORKSPACE = Path(r'E:\JARVIS')
DEFAULT_CHROMIUM = r'C:\Program Files\JARVISBrowserLab\chrome.exe'
PLAYWRIGHT_CHROMIUM = PureWindowsPath('ms-playwright') / 'chromium-1208' / 'chrome-win64' / 'chrome.exe'
RESTRICTED_SID = 'S-1-5-21-2213057978-1848420950-3946800094-1006'
CAPTURE_MS = 5000
VIRTUAL_MS = 1000
WALL_MS = 30000
CLEANUP_MS = 6000
MAX_DOM = 65536
MAX_STDERR = 262144
MAX_INTERNAL_LOG = 1048576
MAX_PROCESSES = 128
PROCESS_TYPES = ('unknown','browser','renderer','gpu-process','utility','network-service','crashpad-handler')
ENVIRONMENT_MODES = ('minimal', 'windows_standard')
JOB_LAUNCH_MODES = ('job_list', 'guarded_job_list', 'guarded_assign')
LOGGING_MODES = ('disabled', 'verbose')
LOG_ERROR_CATEGORIES = ('network_service_crash_reported','access_denied_reported',
                        'sandbox_error_reported','invalid_handle_reported','job_error_reported',
                        'initialization_error_reported','library_load_error_reported',
                        'ipc_error_reported','fatal_error_reported')
JOB_LIMIT_FLAGS = 0x2008  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS; no breakaway.
JOB_ACTIVE_PROCESS_LIMIT = 64
PROCESS_CREATION_FLAGS = 0x08080404  # NO_WINDOW | EXTENDED_STARTUPINFO | UNICODE | SUSPENDED.
JOB_EVENT_NAMES = {1:'end_of_job_time', 2:'end_of_process_time', 3:'active_process_limit',
                   4:'active_process_zero', 6:'new_process', 7:'exit_process',
                   8:'abnormal_exit_process', 9:'process_memory_limit', 10:'job_memory_limit',
                   11:'notification_limit', 12:'job_cycle_time_limit', 13:'silo_terminated'}
JOB_TRACE_STAGES = frozenset(
    ('worker_job_query', 'ambient_limits_query', 'ambient_ui_query', 'ambient_ui_verify',
     'port_create', 'port_associate', 'guard_port_associate', 'job_list_attribute',
     'process_create', 'guard_membership', 'supervisor_absent_before_assign',
     'supervisor_assign', 'root_verification', 'resume_thread',
     'terminate_supervisor', 'terminate_guard') +
    tuple(role+'_'+stage for role in ('supervisor','guard')
          for stage in ('create','limits_set','limits_query','ui_query','limits_verify')))
JOB_LIMIT_FIELDS = ('limit_flags','active_process_limit','ui_restrictions','process_memory_limit',
                    'job_memory_limit','process_time_limit','job_time_limit','min_working_set',
                    'max_working_set','affinity','priority_class','scheduling_class')
STANDARD_WINDOWS_PATH_VARIABLES = (
    'PROGRAMDATA', 'ALLUSERSPROFILE', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
    'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432',
)
STANDARD_WINDOWS_VALUE_VARIABLES = ('PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS')

HTML = (
    '<!doctype html><html><head><meta charset="utf-8">'
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
    'script-src \'nonce-jarvisDiagnostic1\'; connect-src \'none\'; '
    'base-uri \'none\'; form-action \'none\'">'
    '<title>JARVIS synthetic diagnostic</title></head><body>'
    '<button id="run">synthetic</button><output id="result">pending</output>'
    '<script nonce="jarvisDiagnostic1">'
    'document.getElementById("run").addEventListener("click",()=>{'
    'document.getElementById("result").textContent="DIAGNOSTIC_CLICK_OK";'
    'document.body.dataset.clicked="yes";});'
    'setTimeout(()=>{document.getElementById("run").click();'
    'document.body.dataset.executed="yes";},50);'
    '</script></body></html>'
)
DATA_URL = 'data:text/html;base64,' + base64.b64encode(HTML.encode('ascii')).decode('ascii')


class DiagnosticError(RuntimeError):
    def __init__(self, stage, code=0):
        if not re.fullmatch(r'[a-z_]{1,64}', stage):stage = 'diagnostic_error'
        super().__init__(stage)
        self.stage = stage
        self.code = code if type(code) is int and 0 <= code <= 4294967295 else 0


def validate_environment_mode(value):
    if type(value) is not str or value not in ENVIRONMENT_MODES:
        raise DiagnosticError('invalid_environment_mode')
    return value


def validate_job_launch_mode(value):
    if type(value) is not str or value not in JOB_LAUNCH_MODES:
        raise DiagnosticError('invalid_job_launch_mode')
    return value


def validate_logging_mode(value, *, environment_mode='minimal', job_launch_mode='job_list'):
    if type(value) is not str or value not in LOGGING_MODES:
        raise DiagnosticError('invalid_logging_mode')
    if value=='verbose' and (environment_mode!='minimal' or job_launch_mode!='job_list'):
        raise DiagnosticError('logging_requires_minimal_job_list')
    return value


def expected_job_limits():
    return dict.fromkeys(JOB_LIMIT_FIELDS,0) | {
        'limit_flags':JOB_LIMIT_FLAGS,'active_process_limit':JOB_ACTIVE_PROCESS_LIMIT}


def job_limits_match(limits):
    # Windows may return defaults (e.g. SchedulingClass=5) in ignored fields.
    # Exact flags prove those fields are inactive; do not mistake them for limits.
    return (type(limits) is dict and set(limits)==set(JOB_LIMIT_FIELDS) and
            limits['limit_flags']==JOB_LIMIT_FLAGS and
            limits['active_process_limit']==JOB_ACTIVE_PROCESS_LIMIT and limits['ui_restrictions']==0)


def job_diagnostic_state(mode):
    """Bounded numeric/categorical observations, never names, handles or paths."""
    return {'launch_mode':validate_job_launch_mode(mode),'creation_flags':PROCESS_CREATION_FLAGS,
            'worker_in_job':'unknown','ambient_scope':'immediate_job_only',
            'ambient_limits':None,'supervisor_limits':None,'guard_limits':None,
            'guard_empty':None,'stages':[],
            'events':dict.fromkeys((*JOB_EVENT_NAMES.values(),'unknown'),0),
            'guard_events':dict.fromkeys((*JOB_EVENT_NAMES.values(),'unknown'),0),
            'event_scope':'associated_job_or_descendants',
            'sampled_active_max':0,'final_accounting':{'supervisor':None,'guard':None},
            'events_complete':False}


def diagnostic_environment(mode, windows, session, *, source=None):
    """Build a child block only; never modify os.environ or serialize its values.

    minimal preserves the original eight entries. windows_standard adds a
    bounded candidate allowlist; their necessity for this Chromium is unproven.
    Profile, TEMP, APPDATA and PATH remain identical in both modes.
    """
    validate_environment_mode(mode)
    windows = PureWindowsPath(windows);session = PureWindowsPath(session)
    result = {'SystemRoot': str(windows), 'WINDIR': str(windows),
              'PATH': str(windows / 'System32'),
              'TEMP': str(session / 'Temp'), 'TMP': str(session / 'Temp'),
              'USERPROFILE': str(session / 'profile'), 'APPDATA': str(session / 'AppData'),
              'LOCALAPPDATA': str(session / 'LocalAppData')}
    if mode == 'minimal':return result
    # Derive these from known Windows/private paths instead of inheriting them.
    result.update({'COMSPEC': str(windows / 'System32' / 'cmd.exe'),
                   'SYSTEMDRIVE': windows.drive, 'OS': 'Windows_NT',
                   'HOMEDRIVE': session.drive, 'HOMEPATH': str(session / 'profile')[len(session.drive):],
                   'PATHEXT': '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC'})
    source = os.environ if source is None else source
    # No source.items(), copy(), PATH inheritance, API keys, proxy settings,
    # browser overrides, identity names or arbitrary environment expansion.
    for name in STANDARD_WINDOWS_PATH_VARIABLES + STANDARD_WINDOWS_VALUE_VARIABLES:
        value = source.get(name)
        if value is None:continue  # Some x86/architecture entries are optional.
        if type(value) is not str or not value or len(value) > 32767 or any(ord(c) < 32 for c in value):
            raise DiagnosticError('windows_environment_value_invalid')
        if name in STANDARD_WINDOWS_PATH_VARIABLES:
            path = PureWindowsPath(value)
            if (str(path) != value or not path.is_absolute() or
                    re.fullmatch(r'[A-Za-z]:', path.drive) is None or '..' in path.parts or
                    any(':' in part or part.endswith(('.', ' ')) or any(c in part for c in '<>"|?*')
                        for part in path.parts[1:])):
                raise DiagnosticError('windows_environment_value_invalid')
        elif name == 'PROCESSOR_ARCHITECTURE' and value not in ('AMD64','ARM64','x86','IA64'):
            raise DiagnosticError('windows_environment_value_invalid')
        elif name == 'NUMBER_OF_PROCESSORS' and re.fullmatch(r'[1-9][0-9]{0,5}', value) is None:
            raise DiagnosticError('windows_environment_value_invalid')
        result[name] = value
    return result


def chromium_path(value):
    if type(value) is not str or any(ord(c) < 32 or c == '"' for c in value):
        raise DiagnosticError('invalid_chromium_path')
    path = PureWindowsPath(value)
    if (str(path) != value or path.name != 'chrome.exe' or '..' in path.parts or
            any(':' in part or part.endswith(('.', ' ')) for part in path.parts[1:])):
        raise DiagnosticError('invalid_chromium_path')
    if any(value.startswith(prefix) for prefix in ('C:\\Program Files\\', 'C:\\Program Files (x86)\\')):
        return value
    if (('\\jarvis-runtime-preparation-' in value and value.endswith('\\runtime\\chrome.exe')) or
            (any(value.startswith(p) for p in ('E:\\JARVIS\\', 'e:\\JARVIS\\')) and
             ('\\jarvis-runtime-preparation-' in value or value.endswith('\\runtime\\chrome.exe')))):
        return value
    # A single additional diagnostic-only executable; no user-profile prefix
    # allowlist, version wildcard, environment expansion or implicit hash approval.
    local = os.environ.get('LOCALAPPDATA')
    if local and not any(ord(c) < 32 or c == '"' for c in local):
        root = PureWindowsPath(local)
        if (root.is_absolute() and re.fullmatch(r'[A-Za-z]:', root.drive) and str(root) == local
                and '..' not in root.parts
                and not any(':' in part or part.endswith(('.', ' ')) for part in root.parts[1:])
                and value == str(root / PLAYWRIGHT_CHROMIUM)):
            return value
    raise DiagnosticError('invalid_chromium_path')


def no_reparse(path):
    for item in (Path(path), *Path(path).parents):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0) & 0x400:
            raise DiagnosticError('reparse_forbidden')


def bundle_path(value):
    path = Path(value)
    if (not path.is_absolute() or path.parent != WORKSPACE
            or re.fullmatch(r'chromium-diagnostic-review-[a-f0-9]{32}', path.name) is None):
        raise DiagnosticError('invalid_diagnostic_bundle')
    no_reparse(path.parent)
    return path


def command(chromium, session, *, logging_mode='disabled'):
    validate_logging_mode(logging_mode)
    chromium_path(chromium)
    session = Path(session)
    if not session.is_absolute() or any(c in str(session) for c in '\r\n\0"'):
        raise DiagnosticError('invalid_diagnostic_session')
    arguments = [chromium, '--headless', '--dump-dom', '--no-first-run',
            '--no-default-browser-check', '--disable-background-networking',
            '--disable-component-update', '--disable-domain-reliability',
            '--disable-sync', '--disable-quic', '--no-proxy-server',
            '--host-resolver-rules=MAP * ~NOTFOUND',
            '--disable-http-cache',
            '--disable-gpu-shader-disk-cache',
            '--disk-cache-size=0',
            '--media-cache-size=0',
            '--disable-databases',
            '--disable-local-storage',
            '--disable-shared-workers',
            '--disable-features=ServiceWorker,ServiceWorkerCacheStorage,SimpleCache,MediaRouter,OptimizationHints,Translate,CalculateNativeWinOcclusion,CertificateTransparencyComponentUpdater',
            '--disable-extensions',
            '--disable-default-apps',
            '--disable-component-extensions-with-background-pages',
            '--disable-background-timer-throttling',
            '--disable-renderer-backgrounding',
            '--password-store=basic',
            '--use-mock-keychain',
            '--disable-breakpad',
            '--in-process-network',
            '--disable-ipc-flooding-protection',
            '--timeout=' + str(CAPTURE_MS), '--virtual-time-budget=' + str(VIRTUAL_MS),
            '--user-data-dir=' + str(session / 'profile'), DATA_URL]
    if logging_mode=='verbose':
        arguments[-1:-1]=['--enable-logging','--v=1','--log-file='+str(internal_log_path(session))]
    return arguments


def prepare_bundle(*, chromium=DEFAULT_CHROMIUM, environment_mode='minimal', job_launch_mode='job_list',
                   logging_mode='disabled'):
    """Write a new review bundle only; no runtime access, launch or ACL changes."""
    chromium_path(chromium)
    validate_environment_mode(environment_mode)
    validate_job_launch_mode(job_launch_mode)
    validate_logging_mode(logging_mode,environment_mode=environment_mode,job_launch_mode=job_launch_mode)
    no_reparse(WORKSPACE)
    path = bundle_path(WORKSPACE / ('chromium-diagnostic-review-' + uuid.uuid4().hex))
    path.mkdir(exist_ok=False)
    manifest = {'schema': 2, 'mode': 'synthetic_diagnostic_only', 'chromium': chromium,
                'environment_mode': environment_mode,
                'job_launch_mode': job_launch_mode,
                'logging_mode': logging_mode, 'max_internal_log_bytes': MAX_INTERNAL_LOG,
                'fixture_sha256': hashlib.sha256(HTML.encode('ascii')).hexdigest(),
                'capture_ms': CAPTURE_MS, 'virtual_ms': VIRTUAL_MS, 'wall_ms': WALL_MS,
                'production_launch_allowed': False, 'repository_audit': 'not_performed'}
    with (path / 'manifest.json').open('x', encoding='ascii') as file:
        json.dump(manifest, file, indent=2)
    with (path / 'fixture.html').open('x', encoding='ascii') as file:file.write(HTML)
    return path


def read_bundle(path):
    path = bundle_path(path)
    no_reparse(path)
    no_reparse(path / 'manifest.json')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:raise DiagnosticError('duplicate_manifest_field')
            result[key] = value
        return result
    with (path / 'manifest.json').open(encoding='ascii') as file:text = file.read(4097)
    if len(text) > 4096:raise DiagnosticError('manifest_too_large')
    try:manifest = json.loads(text, object_pairs_hook=unique)
    except (ValueError, UnicodeError):raise DiagnosticError('manifest_invalid') from None
    if type(manifest) is not dict:raise DiagnosticError('manifest_invalid')
    expected = {'schema': 2, 'mode': 'synthetic_diagnostic_only',
                'chromium': chromium_path(manifest.get('chromium')),
                'environment_mode': validate_environment_mode(manifest.get('environment_mode')),
                'job_launch_mode': validate_job_launch_mode(manifest.get('job_launch_mode')),
                'logging_mode': validate_logging_mode(manifest.get('logging_mode'),
                    environment_mode=manifest.get('environment_mode'),job_launch_mode=manifest.get('job_launch_mode')),
                'max_internal_log_bytes': MAX_INTERNAL_LOG,
                'fixture_sha256': hashlib.sha256(HTML.encode('ascii')).hexdigest(),
                'capture_ms': CAPTURE_MS, 'virtual_ms': VIRTUAL_MS, 'wall_ms': WALL_MS,
                'production_launch_allowed': False, 'repository_audit': 'not_performed'}
    if (manifest != expected or any(type(manifest[k]) is not type(v) for k, v in expected.items())):
        raise DiagnosticError('manifest_mismatch')
    no_reparse(path / 'fixture.html')
    with (path / 'fixture.html').open('rb') as file:fixture = file.read(len(HTML) + 1)
    if fixture != HTML.encode('ascii'):raise DiagnosticError('fixture_mismatch')
    return manifest


def require_unused_bundle(path):
    for name in ('active-lease.json','session','report.json','watchdog-report.json'):
        try:(path / name).lstat()
        except FileNotFoundError:continue
        raise DiagnosticError('previous_diagnostic_requires_review')


@dataclass
class ProcessFact:
    pid: int
    sequence: int
    identity: str = 'unknown'
    membership: str = 'unknown'
    exited: bool = False
    open_error: int = 0
    token_error: int = 0
    job_error: int = 0
    instance_verified: bool = False
    process_type: str = 'unknown'
    exit_code: int | None = None
    exit_observed_ms: int | None = None
    exit_phase: str = 'unknown'


class ProcessLedger:
    """Job notifications and snapshots, never system-wide PID/parent heuristics."""
    def __init__(self):self.facts = [];self.current = {};self.births = {}
    def observe(self, pid, *, creation=None):
        if type(pid) is not int or not 1 <= pid <= 4294967295:
            raise DiagnosticError('invalid_observed_pid')
        fact = self.current.get(pid)
        if fact is not None:
            if creation is not None and self.births.get(fact.sequence)==creation:return fact
            if creation is None and not fact.exited:return fact
        if len(self.facts) >= MAX_PROCESSES:raise DiagnosticError('process_observation_limit')
        fact = ProcessFact(pid, len(self.facts))
        self.facts.append(fact);self.current[pid] = fact
        if creation is not None:self.births[fact.sequence] = creation
        return fact
    @property
    def complete(self):
        return bool(self.facts) and all(f.instance_verified and f.identity == 'verified' and
                                       f.membership == 'verified' for f in self.facts)


def technical_process_type(arguments):
    """Reduce transient Windows argv to a fixed enum; never retain argv values."""
    kinds=[];subtypes=[]
    for argument in arguments[1:]:
        if argument=='--':break
        if argument=='--type' or argument=='--utility-sub-type':return 'unknown'
        if argument.startswith('--type='):kinds.append(argument[7:])
        if argument.startswith('--utility-sub-type='):subtypes.append(argument[19:])
    if len(kinds)!=1 or len(subtypes)>1:return 'unknown'
    kind=kinds[0]
    if kind=='utility' and subtypes==['network.mojom.NetworkService']:return 'network-service'
    return kind if kind in PROCESS_TYPES and kind not in ('browser','network-service') else 'unknown'


def process_observation(fact):
    """Export only technical evidence. PIDs/birth times/token details stay local."""
    verified=fact.instance_verified and fact.identity=='verified' and fact.membership=='verified'
    return {'process_type':fact.process_type if verified else 'unknown',
            'membership':'verified' if verified else 'unknown',
            'exit_code':fact.exit_code if verified else None,
            'exit_observed_ms':fact.exit_observed_ms if verified else None,
            'exit_phase':fact.exit_phase if verified else 'unknown'}


def monitor(backend, deadline, *, monotonic=time.monotonic):
    """Capture timeout is NOT a process timeout; inspect only after exit check."""
    while True:
        if backend.root_exited():return 'exited'
        if monotonic() >= deadline:return 'wall_timeout'
        backend.sample(deadline)
        if backend.output_exceeded():raise DiagnosticError('output_limit')
        remaining = deadline - monotonic()
        if remaining <= 0:return 'wall_timeout'
        backend.wait(min(25, max(1, int(remaining * 1000))))


class _Markers(HTMLParser):
    def __init__(self):
        super().__init__();self.body = False;self.output = 0;self.text = [];self.executed = self.clicked = False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'body':
            self.body = True
            self.executed = attrs.get('data-executed') == 'yes'
            self.clicked = attrs.get('data-clicked') == 'yes'
        if tag == 'output' and attrs.get('id') == 'result':self.output += 1
    def handle_endtag(self, tag):
        if tag == 'output' and self.output:self.output -= 1
    def handle_data(self, text):
        if self.output:self.text.append(text)


def capture_dom(path):
    try:
        no_reparse(path)
        with path.open('rb') as file:data = file.read(MAX_DOM + 1)
    except FileNotFoundError:return 'missing', False
    except (OSError, DiagnosticError):return 'unreadable', False
    if len(data) > MAX_DOM:return 'oversized', False
    if not data.strip():return 'empty', False
    try:text = data.decode('utf-8-sig')
    except UnicodeError:return 'invalid_encoding', False
    parser = _Markers()
    try:parser.feed(text)
    except (ValueError, RecursionError):return 'invalid_html', False
    markers = (parser.body and parser.executed and parser.clicked and
               ''.join(parser.text) == 'DIAGNOSTIC_CLICK_OK')
    return ('markers_observed' if markers else 'markers_missing'), bool(markers)


def stderr_categories(path):
    try:
        no_reparse(path)
        with path.open('rb') as file:data = file.read(MAX_STDERR + 1)
    except (OSError, DiagnosticError):return ['stderr_unavailable']
    text = data[:MAX_STDERR].decode('utf-8', errors='replace').lower()
    labels = [('network_service_crash_reported', 'network service crashed'),
              ('access_denied_reported', 'access is denied'),
              ('sandbox_error_reported', 'sandbox'),
              ('invalid_handle_reported', 'invalid handle')]
    return [label for label, needle in labels if needle in text] + (['stderr_truncated'] if len(data) > MAX_STDERR else [])


def internal_log_path(session):
    # No caller-supplied filename, environment override or path in the manifest.
    session=Path(session)
    if not session.is_absolute() or any(c in str(session) for c in '\r\n\0"'):
        raise DiagnosticError('invalid_diagnostic_session')
    return session / 'logs' / 'chrome_debug.log'


@contextmanager
def _open_internal_log(path):
    """Open only the fixed regular file, never a reparse target or hard link."""
    no_reparse(path)
    if os.name=='nt':
        import ctypes as c
        from ctypes import wintypes as w
        import msvcrt
        kernel=c.WinDLL('kernel32',use_last_error=True)
        create=kernel.CreateFileW;create.restype=w.HANDLE
        create.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
        final=kernel.GetFinalPathNameByHandleW;final.restype=w.DWORD
        final.argtypes=[w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD]
        close=kernel.CloseHandle;close.restype=w.BOOL;close.argtypes=[w.HANDLE]
        # Read/write sharing lets the live browser append; deny deletion and
        # open the reparse point itself. This read handle is never inherited.
        handle=create(str(path),0x80000000,3,None,3,0x00200000,None)
        if handle in (None,0,c.c_void_p(-1).value):raise c.WinError(c.get_last_error())
        try:
            resolved=c.create_unicode_buffer(32768)
            length=final(handle,resolved,len(resolved),0)
            if not (0<length<len(resolved) and resolved.value.startswith('\\\\?\\') and
                    os.path.normcase(resolved.value[4:])==os.path.normcase(str(path))):
                raise DiagnosticError('internal_log_path_identity')
            descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except BaseException:
            close(handle);raise
    else:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:file=os.fdopen(descriptor,'rb')
    except BaseException:
        os.close(descriptor);raise
    with file:
        metadata=os.fstat(file.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or
                getattr(metadata,'st_file_attributes',0)&0x400):
            raise DiagnosticError('internal_log_not_regular')
        yield file,metadata.st_size


def _internal_log_categories(data):
    # Return only fixed labels. No regex captures, messages, paths, URLs or IDs.
    text=data.decode('utf-8',errors='replace').lower()
    labels=[]
    predicates=(
        'network service crashed' in text,
        any(term in text for term in ('access is denied','access denied','error_access_denied')),
        any(term in text for term in ('sandbox initialization failed','failed to initialize sandbox','sandbox error')),
        any(term in text for term in ('invalid handle','error_invalid_handle')),
        any(term in text for term in ('assignprocesstojobobject failed','failed to assign process to job','job limit exceeded')),
        any(term in text for term in ('failed to initialize','initialization failed')),
        any(term in text for term in ('failed to load','dll not found','module could not be found')),
        any(term in text for term in ('ipc error','ipc connection failed','mojo connection error')),
        any(term in text for term in (':fatal:','check failed:')),
    )
    for label,observed in zip(LOG_ERROR_CATEGORIES,predicates):
        if observed:labels.append(label)
    return labels


def internal_log_summary(session, logging_mode, *, inspect=True, read=True):
    validate_logging_mode(logging_mode)
    result={'presence':'disabled' if logging_mode=='disabled' else 'not_inspected',
            'size_bytes':None,'size_capped':False,'categories':[]}
    if logging_mode=='disabled' or not inspect:return result
    try:
        with _open_internal_log(internal_log_path(session)) as (file,size):
            data=file.read(MAX_INTERNAL_LOG+1) if read else b''
            observed=max(size,len(data))
            result.update(presence='present',size_bytes=min(observed,MAX_INTERNAL_LOG),
                          size_capped=observed>MAX_INTERNAL_LOG,
                          categories=_internal_log_categories(data[:MAX_INTERNAL_LOG]))
    except FileNotFoundError:result.update(presence='missing',size_bytes=0)
    except (OSError,ValueError,DiagnosticError):
        result.update(presence='unreadable',size_bytes=None,size_capped=False,categories=[])
    return result


def validate_internal_log_summary(value, mode):
    def require(ok):
        if not ok:raise DiagnosticError('worker_report_invalid')
    require(type(value) is dict and set(value)=={'presence','size_bytes','size_capped','categories'})
    require(type(value['presence']) is str and value['presence'] in
            ('disabled','not_inspected','missing','present','unreadable'))
    require(type(value['size_capped']) is bool)
    require(type(value['categories']) is list and len(value['categories'])<=len(LOG_ERROR_CATEGORIES))
    require(all(type(label) is str and label in LOG_ERROR_CATEGORIES for label in value['categories']))
    require(len(value['categories'])==len(set(value['categories'])))
    if mode=='disabled':require(value==internal_log_summary(None,'disabled'))
    else:
        require(value['presence']!='disabled')
        if value['presence']=='present':
            require(type(value['size_bytes']) is int and 0<=value['size_bytes']<=MAX_INTERNAL_LOG)
            require(not value['size_capped'] or value['size_bytes']==MAX_INTERNAL_LOG)
        else:
            require(not value['size_capped'] and not value['categories'])
            if value['presence']=='missing':require(type(value['size_bytes']) is int and value['size_bytes']==0)
            else:require(value['size_bytes'] is None)
    return value


def validate_job_diagnostics(value, mode, *, resumed=False, job_empty=False):
    def require(ok):
        if not ok:raise DiagnosticError('worker_report_invalid')
    template=job_diagnostic_state(mode)
    require(type(value) is dict and set(value)==set(template))
    for key in ('launch_mode','creation_flags','ambient_scope','event_scope','events_complete'):
        require(type(value[key]) is type(template[key]) and value[key]==template[key])
    require(value['worker_in_job'] in ('unknown','yes','no'))
    require(value['guard_empty'] is None or type(value['guard_empty']) is bool)
    for key in ('ambient_limits','supervisor_limits','guard_limits'):
        limits=value[key]
        if limits is None:continue
        require(type(limits) is dict and set(limits)==set(JOB_LIMIT_FIELDS))
        require(all(type(number) is int and 0<=number<=18446744073709551615 for number in limits.values()))
    for key in ('events','guard_events'):
        require(type(value[key]) is dict and set(value[key])==set(template[key]))
        require(all(type(number) is int and 0<=number<=65536 for number in value[key].values()))
    require(type(value['sampled_active_max']) is int and 0<=value['sampled_active_max']<=MAX_PROCESSES)
    require(type(value['final_accounting']) is dict and set(value['final_accounting'])=={'supervisor','guard'})
    for accounting in value['final_accounting'].values():
        if accounting is None:continue
        require(type(accounting) is dict and set(accounting)=={'active','total','terminated'})
        require(all(type(number) is int and 0<=number<=4294967295 for number in accounting.values()))
    require(type(value['stages']) is list and len(value['stages'])<=64)
    for stage in value['stages']:
        require(type(stage) is dict and set(stage)=={'stage','ok','code'})
        require(type(stage['stage']) is str and stage['stage'] in JOB_TRACE_STAGES)
        require(type(stage['ok']) is bool and type(stage['code']) is int and 0<=stage['code']<=4294967295)
        require(not stage['ok'] or stage['code']==0)
    guarded=mode!='job_list'
    if not guarded:
        require(value['guard_limits'] is None and value['guard_empty'] is None)
        require(value['final_accounting']['guard'] is None and not any(value['guard_events'].values()))
    if guarded and job_empty and any(stage['stage']=='guard_create' and stage['ok'] for stage in value['stages']):
        require(value['guard_empty'] is True)
    successful=[stage['stage'] for stage in value['stages'] if stage['ok']]
    if job_empty:
        for role in ('supervisor','guard'):
            if role+'_create' in successful:
                accounting=value['final_accounting'][role]
                require(accounting is not None and accounting['active']==0)
    # Apply pre-resume checks to timeouts and crashes as well as DOM success.
    if resumed or 'resume_thread' in successful:
        require(job_limits_match(value['supervisor_limits']))
        required={'supervisor_create','supervisor_limits_set','supervisor_limits_query',
                  'supervisor_ui_query','supervisor_limits_verify','port_create','port_associate',
                  'job_list_attribute','process_create','root_verification','resume_thread'}
        if guarded:
            require(job_limits_match(value['guard_limits']))
            required.update({'guard_create','guard_limits_set','guard_limits_query','guard_ui_query',
                             'guard_limits_verify','guard_membership','guard_port_associate'})
        if mode=='guarded_assign':required.update({'supervisor_absent_before_assign','supervisor_assign'})
        require(required<=set(successful))
        require(len(successful)==len(set(successful)))
        sequence=['job_list_attribute','process_create']
        if guarded:sequence.append('guard_membership')
        if mode=='guarded_assign':sequence.extend(('supervisor_absent_before_assign','supervisor_assign'))
        sequence.extend(('root_verification','resume_thread'))
        require([successful.index(stage) for stage in sequence]==sorted(successful.index(stage) for stage in sequence))
        resume_index=successful.index('resume_thread')
        require(all(successful.index(stage)<resume_index for stage in required-{'resume_thread'}))
    return value


def validate_report(report):
    """Reject incomplete/extra observations and conflicting security claims."""
    fields = {'schema','mode','production_launch_allowed','isolation_verified','repository_audit',
              'network_isolation','sandbox','identity_scope','restricted_account_tested','root_created',
              'root_identity','root_in_job','exit_code','wait_outcome','job_empty','root_stopped',
              'handles_closed','inspection_complete','process_inventory_complete','inspection_scope',
              'processes','diagnostics','lease_retained','profile_retained','elapsed_ms','dom_status',
              'dom_markers_observed','stderr_categories','status','cleanup_verified','environment_mode',
              'job_launch_mode','job_diagnostics','logging_mode','internal_log','exit_observation_complete'}
    def require(ok):
        if not ok:raise DiagnosticError('worker_report_invalid')
    require(type(report) is dict and set(report) == fields)
    require(type(report['environment_mode']) is str and report['environment_mode'] in ENVIRONMENT_MODES)
    require(type(report['job_launch_mode']) is str and report['job_launch_mode'] in JOB_LAUNCH_MODES)
    require(type(report['logging_mode']) is str and report['logging_mode'] in LOGGING_MODES)
    require(report['logging_mode']!='verbose' or
            (report['environment_mode']=='minimal' and report['job_launch_mode']=='job_list'))
    validate_internal_log_summary(report['internal_log'],report['logging_mode'])
    fixed = {'schema': 2, 'mode': 'synthetic_diagnostic_only', 'production_launch_allowed': False,
             'isolation_verified': False, 'network_isolation': 'not_verified', 'sandbox': 'bypass_not_requested',
             'identity_scope': 'current_standard_operator', 'restricted_account_tested': False,
             'inspection_scope': 'owned_job_only', 'lease_retained': True, 'profile_retained': True}
    require(all(type(report[key]) is type(value) and report[key] == value for key,value in fixed.items()))
    require(report['repository_audit'] == {'status':'not_performed','complete':False} and
            report['repository_audit'].get('complete') is False)
    for key in ('root_created','root_in_job','job_empty','root_stopped','handles_closed','inspection_complete',
                'process_inventory_complete','dom_markers_observed','cleanup_verified','exit_observation_complete'):
        require(type(report[key]) is bool)
    require(report['root_identity'] in ('verified','unknown'))
    require(report['wait_outcome'] in ('not_started','exited','wall_timeout'))
    require(report['exit_code'] is None or type(report['exit_code']) is int and 0 <= report['exit_code'] <= 4294967295)
    require(type(report['elapsed_ms']) is int and 0 <= report['elapsed_ms'] < 3600000)
    require(report['dom_status'] in ('missing','unreadable','empty','oversized','invalid_encoding',
                                     'invalid_html','markers_missing','markers_observed'))
    require(report['status'] in ('synthetic_dom_observed','inconclusive'))
    categories = {'network_service_crash_reported','access_denied_reported','sandbox_error_reported',
                  'invalid_handle_reported','stderr_truncated','stderr_unavailable'}
    require(type(report['stderr_categories']) is list and len(report['stderr_categories']) <= len(categories))
    require(all(type(item) is str and item in categories for item in report['stderr_categories']))
    require(type(report['processes']) is list and len(report['processes']) <= MAX_PROCESSES)
    fact_fields = {'process_type','membership','exit_code','exit_observed_ms','exit_phase'}
    for fact in report['processes']:
        require(type(fact) is dict and set(fact) == fact_fields)
        require(type(fact['membership']) is str and fact['membership'] in ('verified','unknown'))
        require(type(fact['process_type']) is str and fact['process_type'] in PROCESS_TYPES)
        require(fact['exit_code'] is None or type(fact['exit_code']) is int and 0 <= fact['exit_code'] <= 4294967295)
        require(fact['exit_observed_ms'] is None or type(fact['exit_observed_ms']) is int and
                0 <= fact['exit_observed_ms'] <= report['elapsed_ms'])
        require(type(fact['exit_phase']) is str and fact['exit_phase'] in ('unknown','before_cleanup','cleanup_window'))
        verified=fact['membership']=='verified'
        require(verified or (fact['process_type']=='unknown' and fact['exit_code'] is None and
                            fact['exit_observed_ms'] is None and fact['exit_phase']=='unknown'))
        exited=fact['exit_observed_ms'] is not None
        require(exited or (fact['exit_code'] is None and fact['exit_phase']=='unknown'))
        require(not exited or fact['exit_phase']!='unknown')
    require(type(report['diagnostics']) is list and len(report['diagnostics']) <= 256)
    for item in report['diagnostics']:
        require(type(item) is dict and set(item) == {'stage','code'} and type(item['stage']) is str)
        require(re.fullmatch(r'[a-z_]{1,64}',item['stage']) is not None and
                type(item['code']) is int and 0 <= item['code'] <= 4294967295)
    require(report['cleanup_verified'] == (report['job_empty'] and report['root_stopped'] and report['handles_closed']))
    if report['logging_mode']=='verbose' and not report['cleanup_verified']:
        require(report['internal_log']['presence']=='not_inspected')
    require(report['inspection_complete'] == (report['process_inventory_complete'] and bool(report['processes']) and
            all(f['membership'] == 'verified' for f in report['processes'])))
    require(report['exit_observation_complete'] == (report['inspection_complete'] and
            all(f['exit_observed_ms'] is not None and f['process_type']!='unknown' and f['exit_code'] is not None
                for f in report['processes'])))
    validate_job_diagnostics(report['job_diagnostics'],report['job_launch_mode'],
                             resumed=report['status']=='synthetic_dom_observed',job_empty=report['job_empty'])
    if report['status'] == 'synthetic_dom_observed':
        require(not report['internal_log']['size_capped'] and report['internal_log']['presence']!='unreadable')
        require(report['root_created'] and report['root_identity'] == 'verified' and report['root_in_job'] and
                report['dom_markers_observed'] and report['dom_status'] == 'markers_observed' and
                report['wait_outcome'] == 'exited' and report['exit_code'] == 0 and
                report['cleanup_verified'] and not report['diagnostics'])
    return report


def run_diagnostic(bundle, *, approved_chromium_sha256, acknowledge_diagnostic_only=False,
                   _backend_factory=None, _monotonic=time.monotonic):
    """Explicit current-operator experiment. Never changes identity or ACLs.

    Test injection is private to this module's regression tests. Production has
    no dependency on this function, its result or its diagnostic authorization.
    """
    if acknowledge_diagnostic_only is not True:raise DiagnosticError('diagnostic_opt_in_required')
    if type(approved_chromium_sha256) is not str or re.fullmatch(r'[a-f0-9]{64}', approved_chromium_sha256) is None:
        raise DiagnosticError('approved_runtime_hash_required')
    bundle = bundle_path(bundle);manifest = read_bundle(bundle);require_unused_bundle(bundle)
    if _backend_factory is None:
        from jarvis.experimental.chromium_diagnostic_win32 import WindowsDiagnostic
        _backend_factory = WindowsDiagnostic
    backend = _backend_factory()
    # Read-only identity check comes BEFORE reservation or any Chromium launch.
    identity = backend.operator_identity()
    if (type(identity) is not dict or type(identity.get('sid')) is not str or
            re.fullmatch(r'S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}', identity['sid']) is None or
            identity['sid'] == RESTRICTED_SID or identity.get('elevated') is not False):
        raise DiagnosticError('standard_operator_identity_required')
    lease = bundle / 'active-lease.json'
    with lease.open('x', encoding='ascii') as file:
        json.dump({'mode': 'synthetic_diagnostic_only', 'state': 'reserved',
                   'environment_mode': manifest['environment_mode'],
                   'job_launch_mode': manifest['job_launch_mode'],
                   'logging_mode': manifest['logging_mode']}, file)
    result = {'schema': 2, 'mode': 'synthetic_diagnostic_only',
              'environment_mode': manifest['environment_mode'],
              'job_launch_mode': manifest['job_launch_mode'],
              'logging_mode': manifest['logging_mode'],
              'job_diagnostics': job_diagnostic_state(manifest['job_launch_mode']),
              'production_launch_allowed': False, 'isolation_verified': False,
              'repository_audit': {'status': 'not_performed', 'complete': False},
              'network_isolation': 'not_verified', 'sandbox': 'bypass_not_requested',
              'identity_scope': 'current_standard_operator', 'restricted_account_tested': False,
              'root_created': False, 'root_identity': 'unknown', 'root_in_job': False,
              'exit_code': None, 'wait_outcome': 'not_started', 'job_empty': False,
              'root_stopped': False, 'handles_closed': False, 'inspection_complete': False,
              'exit_observation_complete': False,
              'process_inventory_complete': False, 'inspection_scope': 'owned_job_only', 'processes': [],
              'diagnostics': [], 'lease_retained': True, 'profile_retained': True}
    started = _monotonic()
    session = bundle / 'session'
    try:
        backend.start(manifest['chromium'], session, approved_chromium_sha256, identity['sid'],
                      environment_mode=manifest['environment_mode'],job_launch_mode=manifest['job_launch_mode'],
                      logging_mode=manifest['logging_mode'])
        result['root_created'] = True
        result['root_identity'] = 'verified';result['root_in_job'] = True
        deadline = started + WALL_MS / 1000
        if _monotonic() >= deadline:result['wait_outcome'] = 'wall_timeout'
        else:
            backend.resume()
            result['wait_outcome'] = monitor(backend, deadline, monotonic=_monotonic)
        if result['wait_outcome'] == 'exited':result['exit_code'] = backend.exit_code()
    except DiagnosticError as error:
        result['diagnostics'].append({'stage': error.stage, 'code': error.code})
    except (OSError, ValueError):
        result['diagnostics'].append({'stage': 'diagnostic_io_error', 'code': 0})
    finally:
        try:
            cleanup = backend.finish(CLEANUP_MS)
            result['job_empty'] = cleanup['job_empty'] is True
            result['root_stopped'] = cleanup['root_stopped'] is True
            result['handles_closed'] = cleanup['handles_closed'] is True
            result['root_created'] = backend.created is True
            result['process_inventory_complete'] = cleanup['inventory_reconciled'] is True
            result['inspection_complete'] = result['process_inventory_complete'] and backend.ledger.complete
            result['processes'] = [process_observation(fact) for fact in backend.ledger.facts]
            result['diagnostics'].extend(cleanup['diagnostics'])
        except (DiagnosticError, OSError, ValueError):
            result['diagnostics'].append({'stage': 'cleanup_not_verified', 'code': 0})
    result['elapsed_ms'] = max(0, int((_monotonic() - started) * 1000))
    result['exit_observation_complete'] = (result['inspection_complete'] and
        all(f['exit_observed_ms'] is not None and f['process_type']!='unknown' and f['exit_code'] is not None
            for f in result['processes']))
    result['job_diagnostics'] = backend.job_diagnostics
    result['dom_status'], markers = capture_dom(session / 'dom.txt')
    result['dom_markers_observed'] = markers and result['root_identity'] == 'verified' and result['root_in_job']
    result['stderr_categories'] = stderr_categories(session / 'stderr.txt')
    verified_cleanup=result['job_empty'] and result['root_stopped'] and result['handles_closed']
    result['internal_log']=internal_log_summary(session,manifest['logging_mode'],inspect=verified_cleanup)
    if result['internal_log']['size_capped']:
        result['diagnostics'].append({'stage':'internal_log_limit','code':0})
    elif result['internal_log']['presence']=='unreadable':
        result['diagnostics'].append({'stage':'internal_log_unreadable','code':0})
    result['status'] = ('synthetic_dom_observed' if result['dom_markers_observed'] and
                        result['wait_outcome'] == 'exited' and result['exit_code'] == 0 and
                        result['job_empty'] and result['root_stopped'] and result['handles_closed']
                        and not result['diagnostics']
                        else 'inconclusive')
    result['cleanup_verified'] = result['job_empty'] and result['root_stopped'] and result['handles_closed']
    validate_report(result)
    # No automatic cleanup, reservation release, policy repair or production grant.
    with (bundle / 'report.json').open('x', encoding='ascii') as file:json.dump(result, file, indent=2)
    return result
