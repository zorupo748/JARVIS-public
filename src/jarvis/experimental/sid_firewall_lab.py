"""Opt-in Windows SID firewall laboratory; never installs/removes rules/users.

Preparation is unprivileged/read-only. Operator owns the local test account,
effective firewall rule and private LAN listeners. Credentials are transient
stdin to the trusted native launcher, never arguments, files or diagnostics.
This is test infrastructure, not production isolation or Chromium integration.
"""
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import threading


class SIDLabError(RuntimeError):
    pass


def _sid(value):
    if type(value) is not str or re.fullmatch(r"S-1-5-21-(?:[1-9][0-9]{0,9}-){3}[1-9][0-9]{0,9}", value) is None:
        raise ValueError("invalid local account SID")
    if any(int(v) > 4294967295 for v in value.split('-')[4:]):
        raise ValueError("invalid local account SID")
    return value


@dataclass(frozen=True, slots=True)
class LocalTestIdentity:
    account_name: str
    sid: str
    standard: bool
    enabled: bool

    def __post_init__(self):
        if type(self.account_name) is not str or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", self.account_name) is None:
            raise ValueError("invalid laboratory account")
        _sid(self.sid)
        if type(self.standard) is not bool or type(self.enabled) is not bool:
            raise ValueError("invalid laboratory identity")


@dataclass(frozen=True, slots=True)
class SIDBlockPlan:
    identity: LocalTestIdentity
    rule_name: str

    def __post_init__(self):
        if type(self.identity) is not LocalTestIdentity or not self.identity.standard or not self.identity.enabled:
            raise ValueError("standard enabled local identity required")
        if type(self.rule_name) is not str or re.fullmatch(r"jarvis-sid-lab-[a-z0-9-]{1,64}", self.rule_name) is None:
            raise ValueError("invalid laboratory rule name")

    @property
    def local_user_sddl(self):
        return "D:(A;;CC;;;" + self.identity.sid + ")"

    def privileged_install_arguments(self):
        """Reviewable specification ONLY. No function executes these arguments."""
        return ("New-NetFirewallRule", "-Name", self.rule_name, "-DisplayName", self.rule_name,
                "-Direction", "Outbound", "-Action", "Block", "-Enabled", "True", "-Profile", "Any",
                "-Protocol", "Any", "-LocalAddress", "Any", "-RemoteAddress", "Any",
                "-LocalPort", "Any", "-RemotePort", "Any", "-Program", "Any",
                "-LocalUser", self.local_user_sddl)


@dataclass(frozen=True, slots=True)
class ControlledEndpoint:
    protocol: str
    address: str
    port: int

    def __post_init__(self):
        if type(self.protocol) is not str or self.protocol not in {"tcp", "udp"} or type(self.address) is not str:
            raise ValueError("invalid controlled endpoint")
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError:
            raise ValueError("invalid controlled endpoint") from None
        if ("%" in self.address or str(address) != self.address or address.is_global or address.is_multicast
                or address.is_unspecified or not (address.is_loopback or address.is_private)
                or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
                or type(self.port) is not int or not 1 <= self.port <= 65535):
            raise ValueError("controlled local/LAN endpoint required")

    @property
    def specification(self):
        return self.protocol + "," + self.address + "," + str(self.port)


def _read_powershell(script, parameters):
    if os.name != "nt":
        raise SIDLabError("windows_required")
    # Fixed scripts, restricted parameters, no shell interpolation/credential.
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, *parameters],
        capture_output=True, text=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise SIDLabError("read_only_inspection_failed")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise SIDLabError("invalid_inspection_report") from None


def inspect_local_identity(account_name):
    # Validate before PowerShell sees the supplied name. GetAuthorizationGroups
    # resolves indirect membership; failure is unknown, never standard=True.
    LocalTestIdentity(account_name, "S-1-5-21-1-2-3-1001", True, True)
    script = """& { param($name)
$ErrorActionPreference='Stop'
$u=Get-LocalUser -Name $name
$c=New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine')
try {
 $p=[System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($c,$name)
 if ($null -eq $p -or $p.Sid.Value -ne $u.SID.Value) { throw 'identity' }
 $g=$p.GetAuthorizationGroups()
 try { $admin=@($g | Where-Object {$_.Sid.Value -eq 'S-1-5-32-544'}).Count -ne 0 }
 finally {$g.Dispose();$p.Dispose()}
 @{account_name=$u.Name;sid=$u.SID.Value;standard=(!$admin);enabled=[bool]$u.Enabled}|ConvertTo-Json -Compress
} finally {$c.Dispose()}
} """
    # Assembly is an OS component, never downloaded.
    script = "Add-Type -AssemblyName System.DirectoryServices.AccountManagement; " + script
    data = _read_powershell(script, [account_name])
    try:
        return LocalTestIdentity(**data)
    except (TypeError, ValueError):
        raise SIDLabError("invalid_identity_report") from None


def validate_effective_rule(plan):
    if type(plan) is not SIDBlockPlan:
        raise ValueError("invalid SID block plan")
    script = """& { param($name)
$ErrorActionPreference='Stop'
$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name)
if ($r.Count -ne 1) { throw 'ambiguous rule' }
$r=$r[0];$s=$r|Get-NetFirewallSecurityFilter;$a=$r|Get-NetFirewallApplicationFilter
$p=$r|Get-NetFirewallPortFilter;$n=$r|Get-NetFirewallAddressFilter
@{name=$r.Name;enabled=[string]$r.Enabled;direction=[string]$r.Direction;action=[string]$r.Action;
 profile=[string]$r.Profile;local_user=$s.LocalUser;program=$a.Program;protocol=[string]$p.Protocol;
 local_port=[string]$p.LocalPort;remote_port=[string]$p.RemotePort;
 local_address=[string]$n.LocalAddress;remote_address=[string]$n.RemoteAddress;
 profiles_enabled=(@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {!$_.Enabled}).Count -eq 0);
 services_running=((Get-Service BFE).Status -eq 'Running' -and (Get-Service MpsSvc).Status -eq 'Running')}|ConvertTo-Json -Compress
} """
    return rule_report_matches(plan, _read_powershell(script, [plan.rule_name]))


def rule_report_matches(plan, report):
    if type(plan) is not SIDBlockPlan or type(report) is not dict:
        return False
    expected = dict(name=plan.rule_name, enabled="True", direction="Outbound", action="Block", profile="Any",
        local_user=plan.local_user_sddl, program="Any", protocol="Any", local_port="Any", remote_port="Any",
        local_address="Any", remote_address="Any", profiles_enabled=True, services_running=True)
    return all(type(report.get(k)) is type(v) and report[k] == v for k, v in expected.items())


@dataclass(frozen=True, slots=True)
class SIDProbeObservation:
    status: str
    expected_sid: str
    root_identity_verified: bool
    child_identity_verified: bool
    attempts: tuple[str, ...]
    cleanup_complete: bool
    remaining_pids: tuple[int, ...] | None = None
    process_created: bool = False
    root_in_job: bool = False
    root_exited: bool = False
    root_exit_code: int | None = None
    child_verified_indices: tuple[int, ...] = ()
    diagnostics: tuple[tuple[str, int], ...] = ()
    root_pid: int | None = None


_DIAGNOSTIC_STAGES = frozenset({"job_create", "job_limits", "process_create", "job_assign", "token_open",
    "root_identity", "root_job", "resume", "wait", "wait_timeout", "exit_code", "probe_result",
    "probe_incomplete", "terminate_root", "cleanup_wait", "terminate_job", "job_query", "job_not_empty",
    "close_token", "close_thread", "close_process", "close_job", "main"})
_ATTEMPTS = frozenset({"error", "echo_received", "denied_10013", "timeout", "udp_sent"})


def parse_probe_report(stdout, expected_sid, endpoint_count, *, returncode=0):
    """Preserve bounded helper facts independently of cleanup certification.

    Listener counts are NOT input: they cannot authenticate traffic ownership.
    Unknown/raw diagnostics are omitted and make the report inconclusive.
    """
    _sid(expected_sid)
    if type(endpoint_count) is not int or not 1 <= endpoint_count <= 8:
        raise ValueError("invalid endpoint count")
    if type(stdout) is bytes:
        stdout = stdout.decode('ascii', errors='replace')
    if type(stdout) is not str or len(stdout) > 16384:
        return SIDProbeObservation("inconclusive", expected_sid, False, False, (), False)
    fields, attempts, children, diagnostics = {}, [], [], []
    malformed = False
    for line in stdout.splitlines():
        name, separator, value = line.partition('=')
        if not separator:
            malformed = True
        elif name == "attempt":
            if value in _ATTEMPTS and len(attempts) < endpoint_count:
                attempts.append(value)
            else:
                malformed = True
        elif name == "child_verified":
            if value.isascii() and value.isdecimal() and len(value) <= 1 and int(value) < endpoint_count and int(value) not in children:
                children.append(int(value))
            else:
                malformed = True
        elif name == "diag":
            stage, comma, code = value.partition(',')
            if stage in _DIAGNOSTIC_STAGES and comma and code.isascii() and code.isdecimal() and len(code) <= 10 and int(code) <= 4294967295 and len(diagnostics) < 32:
                diagnostics.append((stage, int(code)))
            else:
                malformed = True
        elif name in {"report_version", "process_created", "root_pid", "root_identity", "root_in_job",
                      "child_identity", "root_exited", "root_stopped", "root_exit_code", "job_empty", "handles_closed"}:
            if name in fields:
                fields[name] = None
                malformed = True
            else:
                fields[name] = value
        else:
            malformed = True
    def flag(name):
        return fields.get(name) == "1"
    root, child = flag("root_identity"), flag("child_identity")
    code = fields.get("root_exit_code")
    exit_code = int(code) if (type(code) is str and len(code) <= 11 and re.fullmatch(r"-?[0-9]+", code)
                             and -2147483648 <= int(code) <= 4294967295) else None
    pid = fields.get("root_pid")
    root_pid = int(pid) if (type(pid) is str and len(pid) <= 10 and pid.isascii() and pid.isdecimal()
                           and 1 <= int(pid) <= 4294967295) else None
    cleanup = (not malformed and returncode == 0 and fields.get("report_version") == "2"
               and flag("job_empty") and flag("root_stopped") and flag("handles_closed"))
    complete = (cleanup and not diagnostics and flag("process_created") and root and flag("root_in_job")
                and child and flag("root_exited") and exit_code is not None
                and children == list(range(endpoint_count)) and len(attempts) == endpoint_count)
    return SIDProbeObservation("probe_completed" if complete else "inconclusive", expected_sid, root, child,
        tuple(attempts), cleanup, () if cleanup else None, flag("process_created"), flag("root_in_job"),
        flag("root_exited"), exit_code, tuple(children), tuple(diagnostics), root_pid)


def classify_attempts(attempts, positive_before, positive_after, *, effective_rule, identity_verified, cleanup_complete):
    if (any(type(v) is not bool for v in (effective_rule, identity_verified, cleanup_complete))
            or type(attempts) is not tuple or not attempts or len(attempts) > 8
            or any(type(v) is not str or v not in {"denied_10013", "echo_received", "timeout", "error", "udp_sent"} for v in attempts)
            or type(positive_before) is not tuple or type(positive_after) is not tuple
            or len(positive_before) != len(attempts) or len(positive_after) != len(attempts)
            or any(type(v) is not str or v not in {"denied_10013", "echo_received", "timeout", "error", "udp_sent"}
                   for v in positive_before + positive_after)):
        return "inconclusive"
    if not effective_rule or not identity_verified or not cleanup_complete:
        return "inconclusive"
    if any(v == "echo_received" for v in attempts):
        return "network_not_blocked"
    if (all(v == "echo_received" for v in positive_before + positive_after)
            and all(v == "denied_10013" for v in attempts)):
        return "access_denied_observed"
    return "inconclusive"


class RuleLifetimeGuard:
    """No rule deletion API. Unknown/active owned processes forbid removal.

    A privileged operator must consult this guard, and must independently check
    the Job is empty. Cannot constrain an unrelated administrator deleting rules.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._active = set()
        self._unknown = False

    def acquire(self):
        token = object()
        with self._lock:
            self._active.add(token)
        return token

    def settle(self, token, *, confirmed_job_empty):
        with self._lock:
            if token not in self._active or type(confirmed_job_empty) is not bool:
                raise SIDLabError("invalid_cleanup_transition")
            self._active.remove(token)
            if not confirmed_job_empty:
                self._unknown = True

    @property
    def may_remove_rule(self):
        with self._lock:
            return not self._active and not self._unknown


def run_positive_controls(helper_executable, endpoints, blocked_sid):
    """Real trusted helper under the controller identity; no account switching.

    Operator must already have echo listeners on these exact endpoints. A
    received echo proves a working path, not freedom from every possible rule.
    """
    _sid(blocked_sid)
    if (os.name != "nt" or type(helper_executable) is not str or not Path(helper_executable).is_absolute()
            or type(endpoints) is not tuple or not 1 <= len(endpoints) <= 8
            or any(type(v) is not ControlledEndpoint for v in endpoints)):
        raise ValueError("invalid positive control input")
    attempts = []
    identity = None
    for endpoint in endpoints:
        result = subprocess.run([helper_executable, "control", endpoint.specification],
            capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        lines = result.stdout.splitlines()
        if len(lines) != 1 or not lines[0].startswith("control_sid="):
            raise SIDLabError("control_identity_not_verified")
        sid = _sid(lines[0].partition('=')[2])
        if sid == blocked_sid or (identity is not None and identity != sid):
            raise SIDLabError("control_identity_not_verified")
        identity = sid
        attempts.append({1:"echo_received",2:"denied_10013",3:"timeout"}.get(result.returncode,"error"))
    return identity, tuple(attempts)


def run_account_probe(plan, helper_executable, endpoints, *, password, guard, timeout_ms=10000):
    """Trusted operator only; requires an ALREADY effective SID rule.

    Launcher is the compiled sid_firewall_probe.cs fixture. Password is sent
    once over stdin, excluded from argv/repr/reports. Python cannot guarantee
    zeroization of immutable strings: never log/persist the supplied password.
    This function does not compile, grant ACLs, install rules or create accounts.
    """
    if (type(plan) is not SIDBlockPlan or type(guard) is not RuleLifetimeGuard
            or type(endpoints) is not tuple or not 1 <= len(endpoints) <= 8
            or any(type(v) is not ControlledEndpoint for v in endpoints)
            or type(password) is not str or not password or '\n' in password or '\r' in password
            or type(timeout_ms) is not int or not 1000 <= timeout_ms <= 30000
            or type(helper_executable) is not str or not Path(helper_executable).is_absolute()):
        raise ValueError("invalid laboratory launch input")
    if inspect_local_identity(plan.identity.account_name) != plan.identity or not validate_effective_rule(plan):
        raise SIDLabError("account_or_effective_rule_not_verified")
    lease = guard.acquire()
    confirmed = False
    try:
        result = subprocess.run([helper_executable, "launch", plan.identity.account_name, plan.identity.sid,
            str(timeout_ms), *(e.specification for e in endpoints)], input=password + '\n',
            capture_output=True, text=True, timeout=timeout_ms / 1000 + 10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        observation = parse_probe_report(result.stdout, plan.identity.sid, len(endpoints), returncode=result.returncode)
        confirmed = observation.cleanup_complete
        return observation
    except subprocess.TimeoutExpired as error:
        partial = parse_probe_report(error.stdout or "", plan.identity.sid, len(endpoints), returncode=-1)
        return SIDProbeObservation("launch_or_cleanup_inconclusive", partial.expected_sid,
            partial.root_identity_verified, partial.child_identity_verified, partial.attempts, False, None,
            partial.process_created, partial.root_in_job, partial.root_exited, partial.root_exit_code,
            partial.child_verified_indices, partial.diagnostics, partial.root_pid)
    except OSError:
        return SIDProbeObservation("launch_or_cleanup_inconclusive", plan.identity.sid, False, False, (), False)
    finally:
        guard.settle(lease, confirmed_job_empty=confirmed)
