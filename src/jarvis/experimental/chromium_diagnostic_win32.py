"""Native mechanics for the synthetic diagnostic only. No identity switching.

No WMI, VM_READ, credential APIs, ACL writes, policy or firewall operations.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import time

from jarvis.experimental.chromium_diagnostic import (
    DiagnosticError, ProcessLedger, command, no_reparse, MAX_DOM, MAX_STDERR,
    MAX_PROCESSES, diagnostic_environment, validate_environment_mode, validate_job_launch_mode,
    JOB_ACTIVE_PROCESS_LIMIT, JOB_LIMIT_FLAGS, PROCESS_CREATION_FLAGS, JOB_EVENT_NAMES,
    job_limits_match, job_diagnostic_state, validate_logging_mode, internal_log_summary, technical_process_type,
)


class WindowsDiagnostic:
    def __init__(self):
        if os.name != 'nt':raise DiagnosticError('windows_required')
        import ctypes as c
        from ctypes import wintypes as w
        self.c = c;self.w = w
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.adv = c.WinDLL('advapi32', use_last_error=True)
        self.handles = [];self.ledger = ProcessLedger();self.created = False
        self.job = None;self.guard = None;self.port = None;self.process = None;self.thread = None
        self.pid = None;self.root_sid = None;self.session = None;self.failures = []
        self.job_diagnostics = job_diagnostic_state('job_list');self.ready = False
        self.logging_mode = 'disabled'
        self.tracked = {};self.observation_gaps = False;self.cleanup_started = False
        self.observation_started = None;self.chromium = None
        class Startup(c.Structure):
            _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR), ('title', w.LPWSTR)] + [
                (name, w.DWORD) for name in ('x','y','xsize','ysize','xchars','ychars','fill','flags')] + [
                ('show', w.WORD), ('reserved_size', w.WORD), ('reserved_bytes', c.c_void_p),
                ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]
        class StartupEx(c.Structure):_fields_ = [('startup', Startup), ('attributes', c.c_void_p)]
        class ProcessInfo(c.Structure):_fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]
        class Security(c.Structure):_fields_ = [('length', w.DWORD), ('descriptor', c.c_void_p), ('inherit', w.BOOL)]
        class BasicLimits(c.Structure):
            _fields_ = [('process_time', c.c_int64), ('job_time', c.c_int64), ('flags', w.DWORD),
                        ('min_ws', c.c_size_t), ('max_ws', c.c_size_t), ('active', w.DWORD),
                        ('affinity', c.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class Limits(c.Structure):
            _fields_ = [('basic', BasicLimits), ('io', c.c_uint64 * 6),
                        ('process_memory', c.c_size_t), ('job_memory', c.c_size_t),
                        ('peak_process_memory', c.c_size_t), ('peak_job_memory', c.c_size_t)]
        class Accounting(c.Structure):
            _fields_ = [(name, c.c_int64) for name in ('user','kernel','period_user','period_kernel')] + [
                (name, w.DWORD) for name in ('faults','total','active','terminated')]
        class Port(c.Structure):_fields_ = [('key', c.c_void_p), ('port', w.HANDLE)]
        class Pids(c.Structure):_fields_ = [('assigned', w.DWORD), ('count', w.DWORD), ('pids', c.c_size_t * MAX_PROCESSES)]
        self.StartupEx = StartupEx;self.ProcessInfo = ProcessInfo;self.Security = Security
        self.Limits = Limits;self.Accounting = Accounting;self.Port = Port;self.Pids = Pids
        pointer = c.c_void_p;dword = w.DWORD;pdword = c.POINTER(dword)
        def api(dll, name, result, *args):
            fn = getattr(dll, name);fn.restype = result;fn.argtypes = list(args);return fn
        self.close = api(self.kernel, 'CloseHandle', w.BOOL, w.HANDLE)
        self.current = api(self.kernel, 'GetCurrentProcess', w.HANDLE)
        self.open_token = api(self.adv, 'OpenProcessToken', w.BOOL, w.HANDLE, dword, c.POINTER(w.HANDLE))
        self.token_info = api(self.adv, 'GetTokenInformation', w.BOOL, w.HANDLE, c.c_int, pointer, dword, pdword)
        self.sid_text = api(self.adv, 'ConvertSidToStringSidW', w.BOOL, pointer, c.POINTER(pointer))
        self.free = api(self.kernel, 'LocalFree', pointer, pointer)
        self.create_file = api(self.kernel, 'CreateFileW', w.HANDLE, w.LPCWSTR, dword, dword,
                               c.POINTER(Security), dword, dword, w.HANDLE)
        self.read_file = api(self.kernel, 'ReadFile', w.BOOL, w.HANDLE, pointer, dword, pdword, pointer)
        self.final_path = api(self.kernel, 'GetFinalPathNameByHandleW', dword, w.HANDLE, w.LPWSTR, dword, dword)
        self.file_info = api(self.kernel, 'GetFileInformationByHandleEx', w.BOOL, w.HANDLE, c.c_int, pointer, dword)
        self.create_dir = api(self.kernel, 'CreateDirectoryW', w.BOOL, w.LPCWSTR, pointer)
        self.create_job = api(self.kernel, 'CreateJobObjectW', w.HANDLE, pointer, w.LPCWSTR)
        self.set_job = api(self.kernel, 'SetInformationJobObject', w.BOOL, w.HANDLE, c.c_int, pointer, dword)
        self.query_job = api(self.kernel, 'QueryInformationJobObject', w.BOOL, w.HANDLE, c.c_int, pointer, dword, pdword)
        self.in_job = api(self.kernel, 'IsProcessInJob', w.BOOL, w.HANDLE, w.HANDLE, c.POINTER(w.BOOL))
        self.assign_job = api(self.kernel, 'AssignProcessToJobObject', w.BOOL, w.HANDLE, w.HANDLE)
        self.create_port = api(self.kernel, 'CreateIoCompletionPort', w.HANDLE, w.HANDLE, w.HANDLE, c.c_size_t, dword)
        self.events = api(self.kernel, 'GetQueuedCompletionStatus', w.BOOL, w.HANDLE, pdword,
                          c.POINTER(c.c_size_t), c.POINTER(pointer), dword)
        self.initialize = api(self.kernel, 'InitializeProcThreadAttributeList', w.BOOL, pointer, dword, dword, c.POINTER(c.c_size_t))
        self.update = api(self.kernel, 'UpdateProcThreadAttribute', w.BOOL, pointer, dword, c.c_size_t, pointer, c.c_size_t, pointer, pointer)
        self.delete_attributes = api(self.kernel, 'DeleteProcThreadAttributeList', None, pointer)
        self.create_process = api(self.kernel, 'CreateProcessW', w.BOOL, w.LPCWSTR, w.LPWSTR,
                                  pointer, pointer, w.BOOL, dword, pointer, w.LPCWSTR,
                                  c.POINTER(StartupEx), c.POINTER(ProcessInfo))
        self.resume_thread = api(self.kernel, 'ResumeThread', dword, w.HANDLE)
        self.wait_handle = api(self.kernel, 'WaitForSingleObject', dword, w.HANDLE, dword)
        self.get_exit = api(self.kernel, 'GetExitCodeProcess', w.BOOL, w.HANDLE, pdword)
        self.open_process = api(self.kernel, 'OpenProcess', w.HANDLE, dword, w.BOOL, dword)
        self.terminate_job = api(self.kernel, 'TerminateJobObject', w.BOOL, w.HANDLE, w.UINT)
        self.terminate_process = api(self.kernel, 'TerminateProcess', w.BOOL, w.HANDLE, w.UINT)
        self.windows_dir = api(self.kernel, 'GetWindowsDirectoryW', w.UINT, w.LPWSTR, w.UINT)
        self.get_times = api(self.kernel, 'GetProcessTimes', w.BOOL, w.HANDLE,
                             *([c.POINTER(w.FILETIME)] * 4))
        self.image_name = api(self.kernel, 'QueryFullProcessImageNameW', w.BOOL, w.HANDLE,
                              dword, w.LPWSTR, pdword)
        class UnicodeString(c.Structure):
            _fields_ = [('length', w.USHORT), ('maximum', w.USHORT), ('buffer', pointer)]
        self.UnicodeString = UnicodeString
        # Optional native query: no PEB traversal, VM_READ or stronger fallback.
        self.query_command = None
        try:
            self.query_command = api(c.WinDLL('ntdll'), 'NtQueryInformationProcess',
                                     w.LONG, w.HANDLE, c.c_int, pointer, dword, pdword)
        except (AttributeError, OSError):pass
        self.argv = api(c.WinDLL('shell32'), 'CommandLineToArgvW', c.POINTER(w.LPWSTR),
                        w.LPCWSTR, c.POINTER(c.c_int))

    def require(self, ok, stage):
        if not ok:raise DiagnosticError(stage, self.c.get_last_error())

    def job_check(self, ok, stage, *, code=None):
        error=0 if ok else (self.c.get_last_error() if code is None else code)
        if len(self.job_diagnostics['stages'])>=64:raise DiagnosticError('job_trace_limit')
        self.job_diagnostics['stages'].append({'stage':stage,'ok':bool(ok),'code':error})
        if not ok:raise DiagnosticError(stage,error)

    def query_limits(self, job, role):
        limits=self.Limits();ui=self.w.DWORD()
        self.job_check(self.query_job(job,9,self.c.byref(limits),self.c.sizeof(limits),None),role+'_limits_query')
        self.job_check(self.query_job(job,4,self.c.byref(ui),self.c.sizeof(ui),None),role+'_ui_query')
        basic=limits.basic
        return dict(limit_flags=basic.flags,active_process_limit=basic.active,ui_restrictions=ui.value,
                    process_memory_limit=limits.process_memory,job_memory_limit=limits.job_memory,
                    process_time_limit=basic.process_time,job_time_limit=basic.job_time,
                    min_working_set=basic.min_ws,max_working_set=basic.max_ws,affinity=basic.affinity,
                    priority_class=basic.priority,scheduling_class=basic.scheduling)

    def configure_job(self, role):
        handle=self.create_job(None,None)
        self.job_check(handle not in (None,0,self.c.c_void_p(-1).value),role+'_create')
        self.handles.append(handle)
        # Store immediately so cleanup also covers failure during configuration.
        if role=='guard':self.guard=handle
        else:self.job=handle
        limits=self.Limits();limits.basic.flags=JOB_LIMIT_FLAGS;limits.basic.active=JOB_ACTIVE_PROCESS_LIMIT
        self.job_check(self.set_job(handle,9,self.c.byref(limits),self.c.sizeof(limits)),role+'_limits_set')
        observed=self.query_limits(handle,role);self.job_diagnostics[role+'_limits']=observed
        self.job_check(job_limits_match(observed),role+'_limits_verify',code=0)
        return handle

    def inspect_ambient_job(self):
        member=self.w.BOOL()
        self.job_check(self.in_job(self.current(),None,self.c.byref(member)),'worker_job_query')
        self.job_diagnostics['worker_in_job']='yes' if member.value else 'no'
        if member.value:
            limits=self.query_limits(None,'ambient');self.job_diagnostics['ambient_limits']=limits
            # Only the immediate ambient job is queryable here; no full-chain claim.
            self.job_check(limits['ui_restrictions']==0,'ambient_ui_verify',code=0)

    def own(self, handle, stage):
        self.require(handle not in (None, self.c.c_void_p(-1).value), stage)
        self.handles.append(handle);return handle

    def close_checked(self, handle):
        if not self.close(handle):
            error = DiagnosticError('handle_close', self.c.get_last_error())
            self.failures.append({'stage': error.stage, 'code': error.code})
            raise error

    def identity(self, process):
        c = self.c;w = self.w;token = w.HANDLE()
        self.require(self.open_token(process, 8, c.byref(token)), 'token_open')
        try:
            needed = w.DWORD()
            ok = self.token_info(token, 1, None, 0, c.byref(needed))
            self.require(not ok and c.get_last_error() == 122 and 0 < needed.value <= 65536, 'token_user_size')
            buffer = c.create_string_buffer(needed.value)
            self.require(self.token_info(token, 1, buffer, len(buffer), c.byref(needed)), 'token_user')
            text = c.c_void_p()
            self.require(self.sid_text(c.c_void_p.from_buffer(buffer), c.byref(text)), 'token_sid')
            try:sid = c.wstring_at(text)
            finally:self.require(not self.free(text), 'sid_free')
            elevation = w.DWORD()
            self.require(self.token_info(token, 20, c.byref(elevation), c.sizeof(elevation), c.byref(needed)), 'token_elevation')
            return {'sid': sid, 'elevated': bool(elevation.value)}
        finally:self.close_checked(token)

    def operator_identity(self):return self.identity(self.current())

    def pin_runtime(self, path, expected):
        c = self.c;w = self.w
        try:no_reparse(path)
        except OSError as error:raise DiagnosticError('runtime_path_unavailable', getattr(error, 'winerror', 0)) from None
        # Share READ only; do not allow replacement/write during hashing/launch.
        handle = self.own(self.create_file(path, 0xa0000000, 1, None, 3, 0x00200000, None), 'runtime_open')
        final = c.create_unicode_buffer(32768)
        length = self.final_path(handle, final, len(final), 0)
        self.require(0 < length < len(final) and final.value.startswith('\\\\?\\') and
                     os.path.normcase(final.value[4:]) == os.path.normcase(path), 'runtime_path_identity')
        digest = hashlib.sha256();buffer = c.create_string_buffer(65536);read = w.DWORD()
        while True:
            self.require(self.read_file(handle, buffer, len(buffer), c.byref(read), None), 'runtime_read')
            if not read.value:break
            digest.update(buffer.raw[:read.value])
        if digest.hexdigest() != expected:raise DiagnosticError('runtime_hash_mismatch')

    def pin_directory(self, path):
        """Pin each directory used by our writes; never inherit these handles."""
        no_reparse(path)
        handle = self.own(self.create_file(str(path), 0x80, 7, None, 3, 0x02200000, None), 'directory_pin')
        final = self.c.create_unicode_buffer(32768)
        length = self.final_path(handle, final, len(final), 0)
        self.require(0 < length < len(final) and final.value.startswith('\\\\?\\') and
                     os.path.normcase(final.value[4:]) == os.path.normcase(str(path)), 'directory_identity')
        info = (self.w.DWORD * 2)()
        self.require(self.file_info(handle, 9, info, self.c.sizeof(info)) and
                     info[0] & 0x10 and not info[0] & 0x400, 'directory_reparse')

    def start(self, chromium, session, expected_hash, expected_sid, *, environment_mode='minimal', job_launch_mode='job_list',
              logging_mode='disabled'):
        validate_environment_mode(environment_mode)
        validate_job_launch_mode(job_launch_mode)
        self.logging_mode=validate_logging_mode(logging_mode,environment_mode=environment_mode,job_launch_mode=job_launch_mode)
        self.job_diagnostics=job_diagnostic_state(job_launch_mode)
        self.observation_started=time.monotonic();self.chromium=chromium
        c = self.c;w = self.w;self.session = Path(session);self.root_sid = expected_sid
        self.inspect_ambient_job()
        self.pin_runtime(chromium, expected_hash)
        for directory in reversed(self.session.parents):self.pin_directory(directory)
        # New default-inherited directories only: no Set-Acl/security descriptors.
        self.require(self.create_dir(str(self.session), None), 'session_create_new')
        self.pin_directory(self.session)
        directories=('profile','Temp','AppData','LocalAppData')+(('logs',) if logging_mode=='verbose' else ())
        for name in directories:
            self.require(self.create_dir(str(self.session / name), None), 'session_subdirectory')
            self.pin_directory(self.session / name)
        if job_launch_mode!='job_list':self.configure_job('guard')
        self.configure_job('supervisor')
        self.port = self.create_port(c.c_void_p(-1), None, 0, 1)
        self.job_check(bool(self.port), 'port_create')
        self.handles.append(self.port)
        port = self.Port(1, self.port)
        self.job_check(self.set_job(self.job, 7, c.byref(port), c.sizeof(port)), 'port_associate')
        if self.guard:
            # Separate keys avoid double-counting the guard's forwarded events
            # in the supervisor ledger. Both ports are associated while empty.
            guard_port = self.Port(2, self.port)
            self.job_check(self.set_job(self.guard, 7, c.byref(guard_port), c.sizeof(guard_port)), 'guard_port_associate')
        security = self.Security(c.sizeof(self.Security), None, True)
        stdin = self.own(self.create_file('NUL', 0x80000000, 7, c.byref(security), 3, 0, None), 'stdin_open')
        stdout = self.own(self.create_file(str(self.session / 'dom.txt'), 0x40000000, 3,
                                          c.byref(security), 1, 0x80, None), 'stdout_create_new')
        stderr = self.own(self.create_file(str(self.session / 'stderr.txt'), 0x40000000, 3,
                                          c.byref(security), 1, 0x80, None), 'stderr_create_new')
        size = c.c_size_t()
        ok = self.initialize(None, 2, 0, c.byref(size))
        self.require(not ok and c.get_last_error() == 122 and 0 < size.value <= 65536, 'attribute_size')
        attributes = c.create_string_buffer(size.value)
        self.require(self.initialize(attributes, 2, 0, c.byref(size)), 'attributes_initialize')
        try:
            selected = (w.HANDLE * 3)(stdin, stdout, stderr)
            self.require(self.update(attributes, 0, 0x20002, selected, c.sizeof(selected), None, None), 'handle_list')
            # Assign atomically at CreateProcess, before user code. A watchdog
            # must not leave a suspended root outside the KILL_ON_JOB_CLOSE Job.
            assigned=([self.job] if job_launch_mode=='job_list' else
                      [self.guard,self.job] if job_launch_mode=='guarded_job_list' else [self.guard])
            jobs = (w.HANDLE * len(assigned))(*assigned)
            self.job_check(self.update(attributes, 0, 0x2000d, jobs, c.sizeof(jobs), None, None), 'job_list_attribute')
            startup = self.StartupEx();startup.startup.cb = c.sizeof(startup)
            startup.startup.flags = 0x100;startup.startup.stdin = stdin
            startup.startup.stdout = stdout;startup.startup.stderr = stderr
            startup.attributes = c.cast(attributes, c.c_void_p)
            windows = c.create_unicode_buffer(32768);length = self.windows_dir(windows, len(windows))
            self.require(0 < length < len(windows), 'windows_directory')
            environment = diagnostic_environment(environment_mode, windows.value, self.session)
            block = c.create_unicode_buffer('\0'.join(k + '=' + environment[k] for k in sorted(environment, key=str.upper)) + '\0\0')
            arguments = command(chromium, self.session, logging_mode=logging_mode)
            command_line = subprocess.list2cmdline(arguments)
            if len(command_line) >= 32767:raise DiagnosticError('command_too_long')
            line = c.create_unicode_buffer(command_line);info = self.ProcessInfo()
            # Actual inherited handles + Unicode env; suspended BEFORE Job/identity.
            self.job_check(self.create_process(chromium, line, None, None, True, PROCESS_CREATION_FLAGS,
                                              block, str(self.session), c.byref(startup), c.byref(info)), 'process_create')
            self.created = True;self.pid = info.pid
            self.process = self.own(info.process, 'process_handle');self.thread = self.own(info.thread, 'thread_handle')
        finally:self.delete_attributes(attributes)
        if self.guard:
            member=w.BOOL()
            ok=self.in_job(self.process,self.guard,c.byref(member))
            error=c.get_last_error() if not ok else 0
            self.job_check(ok and member.value,'guard_membership',code=error)
        if job_launch_mode=='guarded_assign':
            member=w.BOOL()
            ok=self.in_job(self.process,self.job,c.byref(member))
            error=c.get_last_error() if not ok else 0
            self.job_check(ok and not member.value,'supervisor_absent_before_assign',code=error)
            self.job_check(self.assign_job(self.job,self.process),'supervisor_assign')
        root = self.track(self.pid, self.process)
        self.job_check(root is not None and root.instance_verified and root.identity=='verified' and
                       root.membership=='verified','root_verification',code=0)
        self.ready=True

    def creation_time(self, handle):
        values=[self.w.FILETIME() for unused in range(4)]
        self.require(self.get_times(handle, *(self.c.byref(value) for value in values)), 'process_times')
        value=values[0].dwLowDateTime | (values[0].dwHighDateTime << 32)
        if not value:raise DiagnosticError('process_creation_unknown')
        return value

    def track(self, pid, handle=None):
        """Bind observations to a handle + birth time, never to an event's PID."""
        opened=handle is None;retained=False
        if opened:
            # SYNCHRONIZE for signal checks; no VM_READ/debug/terminate rights.
            handle=self.open_process(0x101000, False, pid)
            if not handle:self.observation_gaps=True;return None
        try:
            creation=self.creation_time(handle)
            fact=self.ledger.observe(pid,creation=creation)
            if fact.sequence in self.tracked:return fact
            if opened:self.handles.append(handle);retained=True
            self.tracked[fact.sequence]=handle
            fact.instance_verified=True
            self.inspect(fact,handle)
            if fact.identity=='verified' and fact.membership=='verified':
                fact.process_type='browser' if handle==self.process else self.process_type(handle)
            return fact
        except DiagnosticError:
            self.observation_gaps=True
            raise
        finally:
            if opened and not retained:
                try:self.close_checked(handle)
                except DiagnosticError:
                    self.handles.append(handle)  # Retry failed closure during cleanup.
                    raise

    def process_type(self, handle):
        """Only a declared technical role escapes this transient, bounded query."""
        c=self.c;w=self.w
        if self.query_command is None:return 'unknown'
        image=c.create_unicode_buffer(32768);size=w.DWORD(len(image))
        if not self.image_name(handle,0,image,c.byref(size)):return 'unknown'
        if os.path.normcase(image.value)!=os.path.normcase(self.chromium):return 'unknown'
        # Class 60 is an internal Windows interface; failure means unknown.
        # One fixed allocation, one query: no unbounded size/retry or fallback.
        buffer=c.create_string_buffer(65536);returned=w.DWORD();arguments=None
        try:
            if self.query_command(handle,60,buffer,len(buffer),c.byref(returned))!=0:return 'unknown'
            if not c.sizeof(self.UnicodeString)<=returned.value<=len(buffer):return 'unknown'
            value=self.UnicodeString.from_buffer(buffer);base=c.addressof(buffer)
            if (not value.length or value.length%2 or value.length>value.maximum or not value.buffer or
                    value.buffer<base+c.sizeof(value) or value.buffer+value.length>base+returned.value):return 'unknown'
            line=c.wstring_at(value.buffer,value.length//2)
            if '\0' in line:return 'unknown'
            count=c.c_int();arguments=self.argv(line,c.byref(count))
            if not arguments or not 1<=count.value<=32768:return 'unknown'
            return technical_process_type(arguments[:count.value])
        finally:
            if arguments:self.free(c.cast(arguments,c.c_void_p))
            c.memset(buffer,0,len(buffer))

    def poll_tracked(self):
        """A signaled retained handle proves exit, even if its code is 259."""
        for fact in self.ledger.facts:
            if (fact.exited or not fact.instance_verified or fact.identity!='verified' or
                    fact.membership!='verified' or fact.sequence not in self.tracked):continue
            handle=self.tracked[fact.sequence];status=self.wait_handle(handle,0)
            if status==258:continue
            if status!=0:self.observation_gaps=True;continue
            fact.exited=True
            fact.exit_observed_ms=max(0,int((time.monotonic()-self.observation_started)*1000))
            fact.exit_phase='cleanup_window' if self.cleanup_started else 'before_cleanup'
            code=self.w.DWORD()
            if self.get_exit(handle,self.c.byref(code)):fact.exit_code=code.value

    def inspect(self, fact, handle):
        if fact.exited:return
        member = self.w.BOOL()
        if self.in_job(handle, self.job, self.c.byref(member)):
            fact.membership = 'verified' if member.value else 'mismatch'
        else:fact.job_error = self.c.get_last_error()
        try:
            identity = self.identity(handle)
            fact.identity = 'verified' if identity['sid'] == self.root_sid and identity['elevated'] is False else 'mismatch'
        except DiagnosticError as error:fact.token_error = error.code
        if fact.identity == 'mismatch' or fact.membership == 'mismatch':raise DiagnosticError('process_identity_or_job_mismatch')

    def resume(self):
        if not self.ready:raise DiagnosticError('root_not_ready')
        self.ready=False
        previous=self.resume_thread(self.thread)
        # Only DWORD(-1) is an API failure with a meaningful GetLastError.
        self.job_check(previous==1,'resume_thread',
                       code=self.c.get_last_error() if previous==0xffffffff else 0)

    def drain_events(self, *, cleanup=False):
        failures=[]
        for unused in range(256):
            message = self.w.DWORD();key = self.c.c_size_t();pid = self.c.c_void_p()
            if not self.events(self.port, self.c.byref(message), self.c.byref(key), self.c.byref(pid), 0):
                if self.c.get_last_error() == 258:return failures
                raise DiagnosticError('job_events', self.c.get_last_error())
            if key.value not in ((1,2) if self.guard else (1,)):raise DiagnosticError('job_event_key')
            name=JOB_EVENT_NAMES.get(message.value,'unknown')
            counts=self.job_diagnostics['events' if key.value==1 else 'guard_events']
            if counts[name]>=65536:raise DiagnosticError('job_event_limit')
            counts[name]+=1
            stage=('job_event_unknown' if name=='unknown' else
                   'job_limit_event' if message.value in (1,2,3,9,10,11,12,13) else None)
            if stage:
                if not cleanup:raise DiagnosticError(stage,message.value)
                # Continue draining after a limit: exit/new-process events still
                # matter to inventory reconciliation. Accounting proves empty.
                failures.append({'stage':stage,'code':message.value})
            if key.value==1:
                # Exit packets have no generation or status. Count them above,
                # but NEVER apply them to the current owner of a recycled PID.
                if message.value == 6:
                    try:self.track(pid.value)
                    except DiagnosticError as error:
                        if not cleanup:raise
                        failures.append({'stage':error.stage,'code':error.code})
        raise DiagnosticError('job_event_limit')

    def sample(self, deadline):
        self.drain_events()
        # A snapshot supplements best-effort completion notifications. It is
        # bounded to this Job, not a system-wide WMI parent tree or stale PID set.
        pids = self.Pids()
        self.require(self.query_job(self.job, 3, self.c.byref(pids), self.c.sizeof(pids), None), 'job_pid_snapshot')
        self.require(pids.count <= MAX_PROCESSES and pids.count == pids.assigned, 'job_snapshot_incomplete')
        self.job_diagnostics['sampled_active_max']=max(self.job_diagnostics['sampled_active_max'],pids.count)
        for pid in pids.pids[:pids.count]:
            if time.monotonic() >= deadline:return
            self.track(int(pid))
        self.poll_tracked()

    def root_exited(self):
        status = self.wait_handle(self.process, 0)
        if status == 0:return True
        if status == 258:return False
        raise DiagnosticError('root_wait', self.c.get_last_error())

    def wait(self, milliseconds):
        status = self.wait_handle(self.process, milliseconds)
        if status not in (0, 258):raise DiagnosticError('root_wait', self.c.get_last_error())

    def exit_code(self):
        value = self.w.DWORD()
        self.require(self.get_exit(self.process, self.c.byref(value)), 'root_exit_code')
        return value.value

    def output_exceeded(self):
        if self.logging_mode=='verbose':
            log=internal_log_summary(self.session,self.logging_mode,read=False)
            if log['presence']=='unreadable':raise DiagnosticError('internal_log_unreadable')
            if log['size_capped']:raise DiagnosticError('internal_log_limit')
        return ((self.session / 'dom.txt').stat().st_size > MAX_DOM or
                (self.session / 'stderr.txt').stat().st_size > MAX_STDERR)

    def finish(self, timeout_ms):
        failures = list(self.failures);empty = False;stopped = not self.created;reconciled = False;total = None
        deadline = time.monotonic() + timeout_ms / 1000
        self.ready=False
        def failure(stage):failures.append({'stage': stage, 'code': self.c.get_last_error()})
        try:
            # Establish the boundary before our FIRST termination attempt. A
            # delayed packet received later never makes a cleanup exit spontaneous.
            self.poll_tracked()
            self.cleanup_started=True
            for role,job in (('supervisor',self.job),('guard',self.guard)):
                if job:
                    try:self.job_check(self.terminate_job(job,100),'terminate_'+role)
                    except DiagnosticError as error:failures.append({'stage':error.stage,'code':error.code})
            for fact in self.ledger.facts:
                if not fact.exited and fact.sequence in self.tracked:
                    h = self.tracked[fact.sequence]
                    if h != self.process:
                        self.terminate_process(h, 100)
            # The guard still contains the suspended root if explicit assignment failed.
            if self.process:
                try:alive = not self.root_exited()
                except DiagnosticError as error:
                    failures.append({'stage': error.stage, 'code': error.code});alive = True
                if alive and not self.terminate_process(self.process, 100):failure('terminate_root')
            while time.monotonic() < deadline:
                stopped = not self.process or self.root_exited()
                empty=True;accounting_ok=True
                for role,job in (('supervisor',self.job),('guard',self.guard)):
                    if not job:continue
                    accounting = self.Accounting()
                    if not self.query_job(job, 1, self.c.byref(accounting), self.c.sizeof(accounting), None):
                        failure('job_accounting' if role=='supervisor' else 'guard_accounting')
                        empty=False;accounting_ok=False;break
                    empty=empty and accounting.active==0
                    self.job_diagnostics['final_accounting'][role]={
                        'active':accounting.active,'total':accounting.total,'terminated':accounting.terminated}
                    if role=='supervisor':total=accounting.total
                    else:self.job_diagnostics['guard_empty']=accounting.active==0
                if not self.job and not self.guard:empty=not self.created
                if not accounting_ok:break
                if empty and stopped:break
                time.sleep(min(.025, max(0, deadline - time.monotonic())))
            if self.port:
                failures.extend(self.drain_events(cleanup=True) or [])
            self.poll_tracked()
            reconciled = (not self.observation_gaps and total is not None and total == len(self.ledger.facts) and
                          self.ledger.complete)
        except DiagnosticError as error:failures.append({'stage': error.stage, 'code': error.code})
        finally:
            closed = not any(item['stage'] == 'handle_close' for item in failures)
            for handle in reversed(self.handles):
                if not self.close(handle):closed = False;failure('handle_close')
            self.handles.clear()
            self.tracked.clear()
        return {'job_empty': empty, 'root_stopped': stopped, 'handles_closed': closed,
                'inventory_reconciled': reconciled, 'job_total_processes': total, 'diagnostics': failures}
