"""Trusted opt-in Windows Chromium experiment; NOT network isolation.

No account/firewall/ACL modifications, no alternate identity, no debug sockets.
Stock Playwright launches under its own identity; its public connect methods
require network endpoints. This version uses dump-dom, not fake pipe control.
Credentials are transient stdin to the native fixture; never persist/log them.
"""
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from pathlib import Path
import base64
import subprocess

from jarvis.experimental.sid_firewall_lab import (
    SIDLabError, SIDBlockPlan, RuleLifetimeGuard, inspect_local_identity, validate_effective_rule, _DIAGNOSTIC_STAGES,
)

ACCOUNT = "jarvis_browser_lab"
SID = "S-1-5-21-2213057978-1848420950-3946800094-1006"
RULE = "jarvis-sid-lab-outbound-1006"
HTML = ('<html><body><button id="b" onclick="document.getElementById(\'s\').textContent=\'SID_CLICK_OK\'">test</button>'
        '<span id="s">pending</span><script>document.getElementById("b").click();document.body.dataset.js="ran";</script></body></html>')


@dataclass(frozen=True, slots=True)
class ChromiumProcessFact:
    pid: int
    role: str
    identity_verified: bool
    in_job: bool
    inspection_error: int


@dataclass(frozen=True, slots=True)
class ChromiumSIDResult:
    status: str
    process_created: bool
    root_identity_verified: bool
    root_in_job: bool
    exit_code: int | None
    javascript_observed: bool
    button_click_observed: bool
    processes: tuple[ChromiumProcessFact, ...]
    sampled_peak_ws: int
    cpu_ms: int | None
    job_empty: bool
    cleanup_complete: bool
    diagnostics: tuple[tuple[str, int], ...]
    playwright_executed: bool = False
    dom: str = field(default="", repr=False)
    inspection_diagnostics: tuple[tuple[int,str,int], ...] = ()
    observed_network_process_count: int = 0
    stderr_categories: tuple[str, ...] = ()


def preflight():
    identity = inspect_local_identity(ACCOUNT)
    if identity.sid != SID or not identity.standard or not identity.enabled:
        raise SIDLabError("restricted_identity_not_verified")
    plan = SIDBlockPlan(identity, RULE)
    if not validate_effective_rule(plan):
        raise SIDLabError("effective_rule_not_verified")
    return plan


class _DOM(HTMLParser):
    def __init__(self):
        super().__init__(); self.js=False; self.span=False; self.text=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=="body": self.js=attrs.get("data-js")=="ran"
        if tag=="span" and attrs.get("id")=="s": self.span=True
    def handle_endtag(self, tag):
        if tag=="span": self.span=False
    def handle_data(self, data):
        if self.span: self.text.append(data)


def parse_chromium_report(report, dom="", *, returncode=0):
    if type(report) is bytes: report=report.decode('ascii',errors='replace')
    if type(report) is not str or len(report)>65536: report=""
    values={}; processes=[]; diagnostics=[]; inspection_diagnostics=[]; malformed=False
    for line in report.splitlines():
        name,sep,value=line.partition('=')
        if name=="process" and sep:
            parts=value.split(',')
            if (len(parts)==5 and parts[0].isascii() and parts[0].isdecimal() and len(parts[0])<=10
                    and 1<=int(parts[0])<=4294967295 and parts[1] in {"browser","renderer","gpu","network","utility","other","unknown"}
                    and parts[2] in {'0','1'} and parts[3] in {'0','1'} and parts[4].isascii()
                    and parts[4].isdecimal() and len(parts[4])<=10 and int(parts[4])<=4294967295 and len(processes)<64):
                processes.append(ChromiumProcessFact(int(parts[0]),parts[1],parts[2]=='1',parts[3]=='1',int(parts[4])))
            else: malformed=True
        elif name=='inspection_diag' and sep:
            parts=value.split(',')
            if (len(parts)==3 and parts[0].isascii() and parts[0].isdecimal() and len(parts[0])<=10
                    and parts[1] in {'open_process','token_open','job_membership','memory_sample'}
                    and parts[2].isascii() and parts[2].isdecimal() and len(parts[2])<=10
                    and len(inspection_diagnostics)<128):
                inspection_diagnostics.append((int(parts[0]),parts[1],int(parts[2])))
            else:malformed=True
        elif name=="diag" and sep:
            stage,comma,number=value.partition(',')
            if stage in _DIAGNOSTIC_STAGES | {'stdio_setup','process_inspection','close_stdin'} and comma and number.isascii() and number.isdecimal() and len(number)<=10 and int(number)<=4294967295 and len(diagnostics)<32:
                diagnostics.append((stage,int(number)))
            else: malformed=True
        elif name in {'chromium_report','process_created','root_pid','root_identity','root_in_job','root_exited','root_stopped',
                      'root_exit_code','cpu_ms','sampled_peak_ws','inspection_failed','job_empty','handles_closed','network_process_count'} and sep:
            if name in values: malformed=True; values[name]=None
            else: values[name]=value
        else: malformed=True
    def yes(name): return values.get(name)=='1'
    def number(name):
        raw=values.get(name)
        return int(raw) if type(raw) is str and len(raw)<=19 and raw.isascii() and raw.isdecimal() else None
    exit_code=number('root_exit_code'); root_pid=number('root_pid')
    root_fact=any(p.pid==root_pid and p.role=='browser' and p.identity_verified and p.in_job for p in processes)
    inspections=(root_fact and values.get('inspection_failed')=='0' and all(p.identity_verified and p.in_job and p.inspection_error==0 for p in processes))
    cleanup=(not malformed and returncode==0 and values.get('chromium_report')=='1' and yes('root_stopped')
             and yes('job_empty') and yes('handles_closed') and (not yes('process_created') or inspections))
    js=clicked=False
    if type(dom) is str and len(dom.encode('utf-8',errors='replace'))<=16384 and yes('root_identity') and yes('root_in_job') and exit_code==0:
        parser=_DOM();parser.feed(dom);js=parser.js;clicked=''.join(parser.text)=='SID_CLICK_OK'
    success=cleanup and yes('process_created') and yes('root_identity') and yes('root_in_job') and js and clicked and not diagnostics
    return ChromiumSIDResult('dom_observed' if success else 'inconclusive',yes('process_created'),yes('root_identity'),yes('root_in_job'),
        exit_code,js,clicked,tuple(processes),number('sampled_peak_ws') or 0,number('cpu_ms'),yes('job_empty'),cleanup,
        tuple(diagnostics),False,dom if js and clicked else '',tuple(inspection_diagnostics),number('network_process_count') or 0)


def classify_stderr(text):
    """Browser-reported categories, not OS proof or raw profile disclosure."""
    if type(text) is not str:return ()
    limited=text[:65536].lower()
    labels=(('network_service_crash_reported','network service crashed'),
            ('access_denied_reported','access is denied'),('profile_creation_failure_reported','failed to create'),
            ('invalid_handle_reported','invalid handle'),('sandbox_error_reported','sandbox'))
    return tuple(label for label,needle in labels if needle in limited)+(('stderr_truncated',) if len(text)>65536 else ())


def run_chromium_probe(helper, chromium, work, *, password, guard, timeout_ms=15000):
    """Operator bootstrap only. Work/profile must be private disposable paths.

    ACL failure is reported, never repaired. No fallback to current-user launch.
    Sampling cannot prove absence of unobserved/short-lived descendants.
    """
    if (type(password) is not str or not password or any(c in password for c in '\r\n\0')
            or type(guard) is not RuleLifetimeGuard or type(timeout_ms) is not int or not 1000<=timeout_ms<=30000):
        raise ValueError("invalid chromium SID probe input")
    for value in (helper,chromium,work):
        if type(value) is not str or not Path(value).is_absolute() or any(c in value for c in '\r\n\0"'):
            raise ValueError("invalid chromium SID path")
    preflight() # Revalidate immediately before launch, not just runner setup.
    from jarvis.experimental.browser_run_environment import allowed_paths,RunLayout,effective_access_check,verify_installed,controller_sid
    if not allowed_paths(helper,chromium,work):
        raise SIDLabError('approved_programdata_environment_required')
    layout=RunLayout(Path(work).name)
    verify_installed(controller_sid())
    effective_access_check(layout,password) # real token checks, including repo denial
    directory=Path(work);profile=directory/'profile'; profile.mkdir(exist_ok=False)
    stdout=directory/'dom.txt'; stderr=directory/'chromium-error.txt'
    lease=guard.acquire(); observation=None
    try:
        result=subprocess.run([helper,'chromium',ACCOUNT,SID,str(timeout_ms),chromium,str(profile),
            base64.b64encode(HTML.encode()).decode('ascii'),str(stdout),str(stderr)], input=password+'\n',
            capture_output=True,text=True,timeout=timeout_ms/1000+15,creationflags=subprocess.CREATE_NO_WINDOW)
        dom=stdout.read_text(encoding='utf-8') if stdout.is_file() and stdout.stat().st_size<=16384 else ''
        categories=()
        if stderr.is_file():
            with stderr.open(encoding='utf-8',errors='replace') as stream:categories=classify_stderr(stream.read(65537))
        observation=replace(parse_chromium_report(result.stdout,dom,returncode=result.returncode),stderr_categories=categories)
        return observation
    except subprocess.TimeoutExpired as error:
        observation=parse_chromium_report(error.stdout or '',returncode=-1)
        return observation
    except OSError:
        observation=parse_chromium_report('diag=process_create,0\n',returncode=-1)
        return observation
    finally:
        guard.settle(lease,confirmed_job_empty=bool(observation and observation.cleanup_complete))
