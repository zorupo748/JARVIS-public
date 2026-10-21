"""Independent scheduled-worker preparation, no registration/credential store.

This cannot authenticate agent clients or make Python reflection a boundary.
Real dispatch is deliberately gated until protected worker + authenticated IPC
and an independently verified token/Job inspector are supplied by bootstrap.
Task Scheduler timeout/Stop are not proof an entire process family terminated.
"""
from dataclasses import dataclass
from enum import Enum
import threading
import xml.etree.ElementTree as ET

from jarvis.experimental.chromium_sid_lab import SID
from jarvis.experimental.sid_firewall_lab import _sid

NS='http://schemas.microsoft.com/windows/2004/02/mit/task'
ET.register_namespace('',NS)


class WorkerState(str,Enum):
    STARTING='starting'
    RUNNING='running'
    STOPPING='stopping'
    FINISHED='finished'
    UNCERTAIN='uncertain'


@dataclass(frozen=True,slots=True)
class WorkerTaskPlan:
    controller_sid:str
    executable:str=r'C:\Program Files\JARVISBrowserLab\worker.exe'
    task_folder:str='\\JARVISBrowserLab'
    task_name:str='SyntheticWorkerV1'

    def __post_init__(self):
        _sid(self.controller_sid)
        if self.controller_sid==SID or self.executable!=r'C:\Program Files\JARVISBrowserLab\worker.exe' or self.task_folder!='\\JARVISBrowserLab' or self.task_name!='SyntheticWorkerV1':
            raise ValueError('invalid_worker_task_plan')

    @property
    def security_descriptor(self):
        return 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+self.controller_sid+')'

    def xml(self):
        root=ET.Element('{'+NS+'}Task',version='1.2')
        def item(parent,name,text=None,**attributes):
            node=ET.SubElement(parent,'{'+NS+'}'+name,attributes);node.text=text;return node
        item(root,'Triggers') # On-demand only: no registration/logon triggers.
        principal=item(item(root,'Principals'),'Principal',id='Worker')
        item(principal,'UserId',SID);item(principal,'LogonType','Password');item(principal,'RunLevel','LeastPrivilege')
        settings=item(root,'Settings')
        for name,value in (('MultipleInstancesPolicy','IgnoreNew'),('ExecutionTimeLimit','PT60S'),
                           ('AllowStartOnDemand','true'),('Enabled','true'),('AllowHardTerminate','true'),
                           ('DisallowStartIfOnBatteries','false'),('StopIfGoingOnBatteries','false')):
            item(settings,name,value)
        action=item(item(root,'Actions',Context='Worker'),'Exec')
        item(action,'Command',self.executable);item(action,'Arguments','task-synthetic-worker')
        item(action,'WorkingDirectory',r'C:\Program Files\JARVISBrowserLab')
        return ET.tostring(root,encoding='unicode')


def validate_registered_task(plan,xml,descriptor,*,worker_protected):
    """Fail closed on XML/ACL changes. No executable merely inferred from ID."""
    if type(plan) is not WorkerTaskPlan or type(xml) is not str or len(xml)>32768 or descriptor!=plan.security_descriptor or worker_protected is not True:return False
    try:
        if '<!' in xml:return False
        actual=ET.fromstring(xml);expected=ET.fromstring(plan.xml())
        def shape(node):
            return node.tag,tuple(sorted(node.attrib.items())),(node.text or '').strip(),tuple(shape(c) for c in node)
        return shape(actual)==shape(expected)
    except (ET.ParseError,RecursionError):return False


def read_registered_task(plan):
    import subprocess,json,os
    if type(plan) is not WorkerTaskPlan or os.name!='nt':raise ValueError('windows_task_plan_required')
    script="""& {param($folder,$name)
$ErrorActionPreference='Stop';$s=New-Object -ComObject Schedule.Service;$s.Connect()
$t=$s.GetFolder($folder).GetTask($name)
@{xml=$t.Xml;descriptor=$t.GetSecurityDescriptor(7);state=[int]$t.State;instances=@($t.GetInstances(0)|ForEach-Object {$_.InstanceGuid})}|ConvertTo-Json -Compress
} """
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script,plan.task_folder,plan.task_name],capture_output=True,text=True,timeout=15)
    if result.returncode:return None # Missing/inaccessible is not authorization.
    try:return json.loads(result.stdout)
    except ValueError:return None


class WorkerLifecycle:
    """Trusted local protocol skeleton; no sockets, broker or scheduler calls.

    Handles are registered by identity, not attacker-supplied task/PID labels.
    Inspection facts must originate in a future authenticated trusted channel.
    supervisor_lost invalidates releases; it does NOT physically kill a worker.
    No task stop/delete is allowed while termination is unconfirmed.
    """
    def __init__(self):
        self._lock=threading.Lock();self._handle=None;self._state=None;self._pid=None

    def reserve_start(self):
        with self._lock:
            if self._handle is not None:raise RuntimeError('duplicate_worker_start')
            self._handle=object();self._state=WorkerState.STARTING;return self._handle

    def confirm_started(self,handle,*,sid,pid,in_job,standard,ipc_authenticated):
        with self._lock:
            if handle is not self._handle or self._state is not WorkerState.STARTING:raise RuntimeError('invalid_worker_transition')
            if sid!=SID or type(pid) is not int or pid<=0 or in_job is not True or standard is not True or ipc_authenticated is not True:
                self._state=WorkerState.UNCERTAIN;return False
            self._pid=pid;self._state=WorkerState.RUNNING;return True

    def request_stop(self,handle):
        with self._lock:
            if handle is not self._handle or self._state is not WorkerState.RUNNING:raise RuntimeError('invalid_worker_transition')
            self._state=WorkerState.STOPPING

    def supervisor_lost(self):
        with self._lock:
            if self._handle is not None:self._state=WorkerState.UNCERTAIN

    def confirm_stopped(self,handle,*,job_empty,handles_closed,profile_removed):
        with self._lock:
            if handle is not self._handle or self._state not in {WorkerState.STOPPING,WorkerState.UNCERTAIN,WorkerState.STARTING}:raise RuntimeError('invalid_worker_transition')
            if not (job_empty is True and handles_closed is True and profile_removed is True):self._state=WorkerState.UNCERTAIN;return False
            self._state=WorkerState.FINISHED;self._handle=None;self._pid=None;return True

    @property
    def safe_to_unregister(self):
        with self._lock:return self._handle is None


def launch_scheduled_worker(*args,**kwargs):
    # An XML prepared task is not a real authenticated worker implementation.
    # Never Run a constructible/unverified task or silently launch as controller.
    raise RuntimeError('protected_worker_and_authenticated_ipc_not_installed')


def uninstall_review_spec(plan,lifecycle):
    if type(plan) is not WorkerTaskPlan or type(lifecycle) is not WorkerLifecycle or not lifecycle.safe_to_unregister:
        raise RuntimeError('worker_cleanup_not_confirmed')
    return dict(folder=plan.task_folder,name=plan.task_name,require_xml=plan.xml(),
                require_descriptor=plan.security_descriptor,require_no_running_instances=True,
                privileged_operation='DeleteTask_only_after_operator_approval')
