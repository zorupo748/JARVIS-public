"""Windows-only test launcher; no production browser, policy or network hook.

Uses a unique per-run profile, zero capabilities, a suspended process and a
kill-on-close job. Supports the trusted helper and an opt-in Chromium data: DOM
experiment. Does not authenticate executable provenance or claim isolation.
Creating/deleting this profile changes its own per-user storage only. No ACL,
firewall, loopback exemption or system configuration is changed.
"""

import ctypes
import os
import shutil
import subprocess
import uuid
import base64
import time
from ctypes import wintypes as w
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppContainerProbeResult:
    status: str
    profile_name: str
    expected_sid: str
    report: tuple[tuple[str, str], ...]
    exit_code: int | None
    cleanup_complete: bool
    remaining_resources: tuple[str, ...]
    processes: tuple = ()
    sampled_peak_working_set_bytes: int = 0
    document_observed: bool = False
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AppContainerProcessObservation:
    pid: int
    appcontainer: bool | None
    sid: str | None
    capabilities: int | None
    in_job: bool | None
    working_set_bytes: int | None
    inspection_error: int | None


def run_chromium_appcontainer_probe(chromium_directory, html, *, timeout_ms=15000):
    """Trusted fixture only; copy indispensable runtime into the OWN profile.

    No personal-folder ACL changes, network capabilities, debugging TCP port or
    sandbox bypass. CLI dump-dom receives a data: URL, not a network/file URL.
    No Playwright control or claims of comprehensive descendant observation.
    """
    if type(chromium_directory) is not str or type(html) is not str or not 1 <= len(html) <= 8192:
        raise ValueError("invalid chromium appcontainer probe input")
    try:
        if len(html.encode("utf-8")) > 8192:
            raise ValueError("invalid chromium appcontainer probe input")
    except UnicodeEncodeError:
        raise ValueError("invalid chromium appcontainer probe input") from None
    return _run_appcontainer(str(Path(chromium_directory) / "chrome.exe"), (), timeout_ms=timeout_ms,
                             chromium_html=html)


def _copy_chromium_dependencies(source, root, files):
    """Stage only runtime assets, under the caller's freshly owned directory."""
    for filename in ("chrome.dll", "chrome_elf.dll", "icudtl.dat", "resources.pak",
                     "chrome_100_percent.pak", "chrome_200_percent.pak", "v8_context_snapshot.bin"):
        destination = root / filename
        files.append(destination)
        shutil.copyfile(source / filename, destination)
    (root / "locales").mkdir()
    destination = root / "locales/en-US.pak"
    files.append(destination)
    shutil.copyfile(source / "locales/en-US.pak", destination)
    for manifest in source.glob("*.manifest"):
        destination = root / manifest.name
        files.append(destination)
        shutil.copyfile(manifest, destination)


def classify_probe(report, expected_sid, endpoint_count):
    """Interpret fixed helper facts, not a failed launch as blocked traffic."""
    if type(report) is not tuple or any(type(p) is not tuple or len(p) != 2
                                        or any(type(v) is not str for v in p) for p in report):
        return "inconclusive"
    data = dict(report)
    if len(data) != len(report):
        return "inconclusive"
    if data.get("appcontainer") != "1" or data.get("sid") != expected_sid or data.get("capabilities") != "0":
        return "identity_failed"
    outcomes = [data.get("endpoint_" + str(i)) for i in range(endpoint_count)]
    if any(value == "connected" for value in outcomes):
        return "network_not_blocked"
    if outcomes and all(value == "blocked_10013" for value in outcomes):
        return "network_blocked"
    return "inconclusive"


def run_appcontainer_probe(executable, endpoint_specs, *, timeout_ms=10000):
    """Launch the trusted test helper against explicit loopback endpoints only.

    Endpoint specs are 'tcp4:PORT', 'udp4:PORT', 'tcp6:PORT', 'udp6:PORT'.
    Reported blocking requires a started helper, exact SID and no capabilities.
    Listener receipts/positive controls are verified independently by the tests.
    Result always reports cleanup status; leftover resources must be investigated.
    No elevation or fallback to an unrestricted process is attempted.
    """
    return _run_appcontainer(executable, endpoint_specs, timeout_ms=timeout_ms)


def _run_appcontainer(executable, endpoint_specs, *, timeout_ms, chromium_html=None):
    if os.name != "nt":
        raise RuntimeError("windows_required")
    if (type(executable) is not str or type(endpoint_specs) is not tuple
            or not (0 if chromium_html is not None else 1) <= len(endpoint_specs) <= 4 or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30000):
        raise ValueError("invalid appcontainer probe input")
    kinds = set()
    for spec in endpoint_specs:
        if type(spec) is not str:
            raise ValueError("invalid appcontainer probe input")
        kind, separator, port = spec.partition(":")
        if (not separator or kind not in {"tcp4", "udp4", "tcp6", "udp6"}
                or kind in kinds or not 1 <= len(port) <= 5 or not port.isascii() or not port.isdecimal()
                or not 1 <= int(port) <= 65535):
            raise ValueError("invalid appcontainer probe input")
        kinds.add(kind)

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    ole = ctypes.WinDLL("ole32")

    def signature(dll, name, result, *args):
        function = getattr(dll, name)
        function.restype, function.argtypes = result, args
        return function

    class Startup(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                    ("title", w.LPWSTR)] + [(name, w.DWORD) for name in
                    ("x", "y", "xsize", "ysize", "xchars", "ychars", "fill", "flags")] + [
                    ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_bytes", ctypes.c_void_p),
                    ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]

    class StartupEx(ctypes.Structure):
        _fields_ = [("startup", Startup), ("attributes", ctypes.c_void_p)]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]

    class Capabilities(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("capabilities", ctypes.c_void_p),
                    ("count", w.DWORD), ("reserved", w.DWORD)]

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]

    class MemoryCounters(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("faults", w.DWORD)] + [(name, ctypes.c_size_t) for name in
                    ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]

    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", w.DWORD), ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t),
                    ("active_processes", w.DWORD), ("affinity", ctypes.c_size_t),
                    ("priority", w.DWORD), ("scheduling", w.DWORD)]

    class JobLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

    create_profile = signature(userenv, "CreateAppContainerProfile", ctypes.c_long,
                               w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, ctypes.c_void_p, w.DWORD,
                               ctypes.POINTER(ctypes.c_void_p))
    delete_profile = signature(userenv, "DeleteAppContainerProfile", ctypes.c_long, w.LPCWSTR)
    folder_path = signature(userenv, "GetAppContainerFolderPath", ctypes.c_long,
                            w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    convert_sid = signature(advapi, "ConvertSidToStringSidW", w.BOOL,
                            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    free_sid = signature(advapi, "FreeSid", ctypes.c_void_p, ctypes.c_void_p)
    local_free = signature(kernel, "LocalFree", ctypes.c_void_p, ctypes.c_void_p)
    task_free = signature(ole, "CoTaskMemFree", None, ctypes.c_void_p)
    initialize = signature(kernel, "InitializeProcThreadAttributeList", w.BOOL,
                           ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t))
    update = signature(kernel, "UpdateProcThreadAttribute", w.BOOL, ctypes.c_void_p, w.DWORD,
                       ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p)
    delete_attributes = signature(kernel, "DeleteProcThreadAttributeList", None, ctypes.c_void_p)
    create_process = signature(kernel, "CreateProcessW", w.BOOL, w.LPCWSTR, w.LPWSTR,
                               ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
                               ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(StartupEx), ctypes.POINTER(ProcessInfo))
    create_job = signature(kernel, "CreateJobObjectW", w.HANDLE, ctypes.c_void_p, w.LPCWSTR)
    set_job = signature(kernel, "SetInformationJobObject", w.BOOL, w.HANDLE, ctypes.c_int,
                        ctypes.c_void_p, w.DWORD)
    assign_job = signature(kernel, "AssignProcessToJobObject", w.BOOL, w.HANDLE, w.HANDLE)
    resume = signature(kernel, "ResumeThread", w.DWORD, w.HANDLE)
    wait = signature(kernel, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
    terminate = signature(kernel, "TerminateProcess", w.BOOL, w.HANDLE, w.UINT)
    exit_status = signature(kernel, "GetExitCodeProcess", w.BOOL, w.HANDLE, ctypes.POINTER(w.DWORD))
    close = signature(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    open_process = signature(kernel, "OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
    open_token = signature(advapi, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
    token_info = signature(advapi, "GetTokenInformation", w.BOOL, w.HANDLE, ctypes.c_int,
                           ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD))
    in_job = signature(kernel, "IsProcessInJob", w.BOOL, w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL))
    query_job = signature(kernel, "QueryInformationJobObject", w.BOOL, w.HANDLE, ctypes.c_int,
                          ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD))
    terminate_job = signature(kernel, "TerminateJobObject", w.BOOL, w.HANDLE, w.UINT)
    memory_info = signature(ctypes.WinDLL("psapi"), "GetProcessMemoryInfo", w.BOOL,
                            w.HANDLE, ctypes.POINTER(MemoryCounters), w.DWORD)
    create_file = signature(kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD,
                            ctypes.POINTER(SecurityAttributes), w.DWORD, w.DWORD, w.HANDLE)

    def inspect_process(pid):
        handle = open_process(0x1000 | 0x10, False, pid)
        if not handle:
            return AppContainerProcessObservation(pid, None, None, None, None, None, ctypes.get_last_error())
        token = w.HANDLE()
        container, actual_sid, count, membership, ws, error = None, None, None, None, None, None
        try:
            flag = w.BOOL()
            if in_job(handle, job, ctypes.byref(flag)):
                membership = bool(flag.value)
            else:
                error = ctypes.get_last_error()
            counters = MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if memory_info(handle, ctypes.byref(counters), ctypes.sizeof(counters)):
                ws = counters.ws
            else:
                error = ctypes.get_last_error()
            if not open_token(handle, 8, ctypes.byref(token)):
                error = ctypes.get_last_error()
            else:
                def information(kind):
                    needed = w.DWORD()
                    token_info(token, kind, None, 0, ctypes.byref(needed))
                    require(0 < needed.value <= 65536)
                    data = ctypes.create_string_buffer(needed.value)
                    require(token_info(token, kind, data, needed.value, ctypes.byref(needed)))
                    return data
                container = bool(w.DWORD.from_buffer(information(29)).value)
                count = w.DWORD.from_buffer(information(30)).value
                if container:
                    data = information(31)
                    text = ctypes.c_void_p()
                    require(convert_sid(ctypes.c_void_p.from_buffer(data), ctypes.byref(text)))
                    try:
                        actual_sid = ctypes.wstring_at(text)
                    finally:
                        local_free(text)
        except OSError:
            error = ctypes.get_last_error()
        finally:
            if token:
                close(token)
            close(handle)
        return AppContainerProcessObservation(pid, container, actual_sid, count, membership, ws, error)

    def job_pids():
        data = ctypes.create_string_buffer(65536)
        if not query_job(job, 3, data, len(data), None):
            return None
        count = w.DWORD.from_buffer(data, 4).value
        if count > 1024:
            return None
        return tuple((ctypes.c_size_t * count).from_buffer(data, 8))

    def require(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    name = "jarvis-probe-" + uuid.uuid4().hex
    sid, sid_text, folder = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    created = initialized = False
    process, job = ProcessInfo(), None
    files = []
    root = None
    remaining = []
    io_handles = []
    observations, peak_ws, document, diagnostics = {}, 0, False, []
    report, expected, code, status = (), "", None, "launch_failed"
    stage = "profile_creation"
    try:
        require(create_profile(name, name, "Temporary JARVIS test only", None, 0, ctypes.byref(sid)) == 0)
        created = True  # Never delete an existing profile after creation failure.
        require(convert_sid(sid, ctypes.byref(sid_text)))
        expected = ctypes.wstring_at(sid_text)
        require(folder_path(expected, ctypes.byref(folder)) == 0)
        root = Path(ctypes.wstring_at(folder))
        helper, output = root / "jarvis-probe.exe", root / "jarvis-report.txt"
        if chromium_html is not None:
            helper = root / "chrome.exe"
        if helper.exists() or output.exists():
            raise OSError("unexpected_profile_content")
        files.append(helper)
        shutil.copyfile(executable, helper)
        files.append(output)
        if chromium_html is not None:
            stage = "runtime_copy"
            source = Path(executable).parent
            # Chromium's embedded activation context requires its versioned
            # side-by-side manifest alongside the relocated runtime.
            _copy_chromium_dependencies(source, root, files)
        size = ctypes.c_size_t()
        stage = "attribute_setup"
        attribute_count = 2 if chromium_html is not None else 1
        initialize(None, attribute_count, 0, ctypes.byref(size))
        require(0 < size.value <= 65536)
        buffer = ctypes.create_string_buffer(size.value)
        attributes = ctypes.cast(buffer, ctypes.c_void_p)
        require(initialize(attributes, attribute_count, 0, ctypes.byref(size)))
        initialized = True
        capabilities = Capabilities(sid, None, 0, 0)
        require(update(attributes, 0, 0x20009, ctypes.byref(capabilities),
                       ctypes.sizeof(capabilities), None, None))
        startup = StartupEx()
        startup.startup.cb = ctypes.sizeof(StartupEx)
        startup.attributes = attributes
        arguments = [str(helper), str(output), *endpoint_specs]
        if chromium_html is not None:
            stage = "stdio_setup"
            security = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)
            for filename in (output, root / "stderr.txt"):
                if filename != output:
                    files.append(filename)
                handle = create_file(str(filename), 0x40000000, 1, ctypes.byref(security), 2, 0x80, None)
                require(handle and handle != ctypes.c_void_p(-1).value)
                io_handles.append(handle)
            handle = create_file("NUL", 0x80000000, 3, ctypes.byref(security), 3, 0x80, None)
            require(handle and handle != ctypes.c_void_p(-1).value)
            io_handles.append(handle)
            handles = (w.HANDLE * len(io_handles))(*io_handles)
            require(update(attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None))
            startup.startup.flags = 0x100
            startup.startup.stdout, startup.startup.stderr, startup.startup.stdin = io_handles
            url = "data:text/html;base64," + base64.b64encode(chromium_html.encode("utf-8")).decode("ascii")
            arguments = [str(helper), "--headless=new", "--dump-dom", "--timeout=8000",
                         "--virtual-time-budget=1000", "--user-data-dir=" + str(root / "browser-profile"),
                         "--lang=en-US", "--disable-gpu", "--disable-background-networking",
                         "--disable-component-update", "--disable-sync", "--disable-quic",
                         "--disable-breakpad", "--disable-crash-reporter", "--no-first-run",
                         "--no-default-browser-check", "--proxy-server=http://127.0.0.1:9",
                         "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND", url]
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(arguments))
        stage = "create_process"
        require(create_process(str(helper), command, None, None, chromium_html is not None,
                               0x80000 | 4 | 0x08000000, None, str(root), ctypes.byref(startup), ctypes.byref(process)))
        job = create_job(None, None)
        stage = "job_setup"
        require(job)
        limits = JobLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        require(set_job(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        require(assign_job(job, process.process))
        if chromium_html is not None:
            stage = "root_identity"
            observation = inspect_process(process.pid)
            observations[process.pid] = observation
            if observation.appcontainer is not True or observation.sid != expected or observation.capabilities != 0 or observation.in_job is not True:
                status = "identity_failed"
                raise OSError("root_identity_failed")
        require(resume(process.thread) != 0xFFFFFFFF)
        stage = "process_execution"
        status = "inconclusive"
        if chromium_html is None:
            require(wait(process.process, timeout_ms) == 0)
        else:
            deadline = time.monotonic() + timeout_ms / 1000
            while True:
                pids = job_pids()
                if pids is None:
                    diagnostics.append("job_enumeration_failed")
                    pids = (process.pid,)
                sample = [inspect_process(pid) for pid in pids]
                for observation in sample:
                    previous = observations.get(observation.pid)
                    if previous is None or observation.appcontainer is not None:
                        observations[observation.pid] = observation
                peak_ws = max(peak_ws, sum(item.working_set_bytes or 0 for item in sample))
                if wait(process.process, 50) == 0:
                    break
                if time.monotonic() >= deadline:
                    status = "chromium_timeout"
                    raise OSError("probe_timeout")
        value = w.DWORD()
        require(exit_status(process.process, ctypes.byref(value)))
        code = value.value
        if chromium_html is not None:
            # Close inherited output handles before reading their bounded files.
            for handle in io_handles:
                require(close(handle))
            io_handles.clear()
            with output.open("rb") as stream:
                raw = stream.read(65537)
            document = code == 0 and len(raw) <= 65536 and b'<p id="result">JARVIS-APPCONTAINER-DOM-OK</p>' in raw
            status = "document_observed" if document else "chromium_exit_failed" if code != 0 else "document_not_observed"
            diagnostics.append("exit_code:" + str(code))
            with (root / "stderr.txt").open("rb") as stream:
                errors = stream.read(16384)
            for marker, label in ((b"Access is denied", "access_denied"), (b"sandbox", "sandbox_diagnostic"),
                                  (b"Initialize", "initialization_diagnostic"), (b"ERROR", "chromium_error_logged")):
                if marker in errors:
                    diagnostics.append(label)
        elif code == 0:
            with output.open("rb") as stream:
                raw = stream.read(8193)
            if len(raw) <= 8192:
                lines = raw.decode("ascii").splitlines()
                if all(line.count("=") == 1 for line in lines):
                    report = tuple(tuple(line.split("=")) for line in lines)
                    status = classify_probe(report, expected, len(endpoint_specs))
    except (OSError, UnicodeError) as error:
        # Launch failure/inconclusive is never evidence that networking was denied.
        if chromium_html is not None:
            diagnostics.append("failure_stage:" + stage)
            if isinstance(error, OSError):
                diagnostics.append("winerror:" + str(getattr(error, "winerror", None)))
    finally:
        if chromium_html is not None and job:
            if not terminate_job(job, 1):
                remaining.append("job_termination")
            deadline = time.monotonic() + 5
            while True:
                pids = job_pids()
                if pids == ():
                    break
                if pids is None or time.monotonic() >= deadline:
                    remaining.append("job_processes_unknown_or_alive")
                    break
                time.sleep(0.02)
        if process.process and wait(process.process, 0) != 0:
            if not terminate(process.process, 1) or wait(process.process, 5000) != 0:
                remaining.append("process:" + str(process.pid))
        for handle, label in ((process.thread, "thread"), (process.process, "process_handle"), (job, "job")):
            if handle and not close(handle):
                remaining.append(label)
        for handle in io_handles:
            if not close(handle):
                remaining.append("output_handle")
        if initialized:
            delete_attributes(attributes)
        for path in files:
            try:
                path.unlink(missing_ok=True)  # Known files only, never recursive deletion.
            except OSError:
                remaining.append("profile_file:" + path.name)
        if created and delete_profile(name) != 0:
            remaining.append("profile:" + name)
        if created and root is not None:
            try:
                if root.exists():
                    remaining.append("profile_storage:" + name)
            except OSError:
                remaining.append("profile_storage_unknown:" + name)
        if sid:
            free_sid(sid)
        if sid_text:
            local_free(sid_text)
        if folder:
            task_free(folder)
    return AppContainerProbeResult(status, name, expected, report, code, not remaining, tuple(remaining),
                                   tuple(observations.values()), peak_ws, document, tuple(diagnostics))
