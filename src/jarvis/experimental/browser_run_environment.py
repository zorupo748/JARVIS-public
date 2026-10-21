"""Operator-installed ProgramData laboratory, never a repository sandbox.

One active SID session only. Same-SID simultaneous sessions cannot be isolated
by DACLs alone. Existing Windows home/temp permissions are NOT globally revoked.
No administrative install, credential storage or ACL workaround is performed.
"""
from dataclasses import dataclass
import json
from pathlib import Path, PureWindowsPath
import re
import os
import stat
import time
from contextlib import contextmanager, ExitStack
import subprocess
import uuid

from jarvis.experimental.chromium_sid_lab import SID
from jarvis.experimental.sid_firewall_lab import _sid,SIDLabError
from jarvis.experimental.browser_runtime_preparation import digest

ROOT=r'C:\ProgramData\JARVISBrowserLab'
REPOSITORY=r'E:\JARVIS'
CHROME=r'C:\Program Files\JARVISBrowserLab\chrome.exe'
REPOSITORY_PROBE=r'E:\JARVIS\src\jarvis\experimental\chromium_sid_lab.py'
AUDIT_LIMIT=50000  # Counts directories as well as files; never sample a prefix.
AUDIT_SECONDS=120  # Cooperative deadline including enumeration, not just helper.
MUTATION=0x000d0156  # write/append/EA/attributes, delete/delete-child, DACL/owner
READ_CONTENT=0x00020089  # data/list, EA, attributes, READ_CONTROL
EXECUTE=0x20
RX=0x1200a9
SESSION_RW=0x13019f
SESSION_DENY=0x000c0020
OWNER_RIGHTS='S-1-3-4'


class EffectiveAccessError(SIDLabError):
    def __init__(self,report):
        super().__init__('effective_access_not_verified')
        facts=[]
        if type(report) is str and len(report)<=8192:
            for line in report.splitlines():
                match=re.fullmatch(r'environment_access=([0-7]),([0-9]{1,10})',line)
                if match:facts.append(('access',int(match[1]),int(match[2])))
                elif line in {'repository_denial_verified=0','repository_denial_verified=1'}:
                    facts.append(('repository_denial_verified',int(line[-1]),0))
                else:
                    match=re.fullmatch(r'diag=(credential_logon|root_identity|impersonate|revert_identity|close_token|repository_access),([0-9]{1,10})',line)
                    if match:facts.append((match[1],0,int(match[2])))
        self.facts=tuple(facts[:16])


@dataclass(frozen=True,slots=True)
class RunLayout:
    run_id:str
    def __post_init__(self):
        if type(self.run_id) is not str or re.fullmatch(r'[a-f0-9]{32}',self.run_id) is None:
            raise ValueError('invalid_run_id')
    @property
    def helper(self):return str(PureWindowsPath(ROOT)/'trusted'/'launcher.exe')
    @property
    def session(self):return str(PureWindowsPath(ROOT)/'sessions'/self.run_id)
    @property
    def report(self):return str(PureWindowsPath(ROOT)/'control'/('result-'+self.run_id+'.json'))


def allowed_paths(helper,chrome,session):
    if any(type(v) is not str for v in (helper,chrome,session)):return False
    prefix=str(PureWindowsPath(ROOT)/'sessions')+'\\'
    if not session.startswith(prefix):return False
    identifier=session[len(prefix):]
    try:layout=RunLayout(identifier)
    except ValueError:return False
    return helper==layout.helper and chrome==CHROME and session==layout.session


def _no_reparse(path):
    path=Path(path)
    for component in (path,*path.parents):
        metadata=component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata,'st_file_attributes',0)&0x400:
            raise SIDLabError('environment_reparse_forbidden')


def expected_acl(role,controller_sid):
    _sid(controller_sid)
    if controller_sid==SID:raise SIDLabError('controller_must_differ_from_worker')
    masks={'root':{SID:0x1200a0,controller_sid:0x1200a9},
           'trusted':{SID:0x1200a9,controller_sid:0x1200a9},
           'control':{controller_sid:0x1301bf},
           'sessions':{SID:0x1200a0,controller_sid:0x1301bf},
           'session':{controller_sid:0x1f01ff,SID:SESSION_RW}}
    if role not in masks:raise ValueError('invalid_environment_role')
    return {'S-1-5-18':0x1f01ff,'S-1-5-32-544':0x1f01ff,**masks[role]}


def acl_matches(report,role,controller_sid,*,directory=True):
    owner=controller_sid if role=='session' else 'S-1-5-32-544'
    if type(report) is not dict or report.get('protected') is not True or report.get('owner')!=owner:return False
    flags=3 if directory else 0  # OBJECT_INHERIT | CONTAINER_INHERIT
    expected=[]
    if role=='session':
        expected.extend([('AccessDenied',SID,SESSION_DENY,flags),
                         ('AccessDenied',OWNER_RIGHTS,0xc0000,flags)])
    expected.extend(('AccessAllowed',sid,mask,flags) for sid,mask in expected_acl(role,controller_sid).items())
    actual=[]
    if type(report.get('aces')) is not list:return False
    for ace in report['aces']:
        if (type(ace) is not dict or type(ace.get('sid')) is not str or type(ace.get('mask')) is not int
                or type(ace.get('flags')) is not int):return False
        actual.append((ace.get('qualifier'),ace['sid'],ace['mask'],ace['flags']))
    return actual==expected


def verify_installed(controller_sid):
    _sid(controller_sid)
    if not Path(ROOT).is_dir():raise SIDLabError('programdata_environment_missing_or_inaccessible')
    for name,role in (('', 'root'),('trusted','trusted'),('control','control'),('sessions','sessions')):
        path=Path(ROOT)/name;_no_reparse(path)
        if not acl_matches(read_only_acl_report(path),role,controller_sid):raise SIDLabError('environment_acl_not_verified')
    for name in ('launcher.exe','launcher.sha256','installation.json'):
        _no_reparse(Path(ROOT)/'trusted'/name)
        if not acl_matches(read_only_acl_report(Path(ROOT)/'trusted'/name),'trusted',controller_sid,directory=False):
            raise SIDLabError('helper_acl_not_verified')
    helper=Path(ROOT)/'trusted'/'launcher.exe'
    expected=(Path(ROOT)/'trusted'/'launcher.sha256').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[a-f0-9]{64}',expected) or digest(helper)!=expected:
        raise SIDLabError('helper_hash_mismatch')
    marker=Path(ROOT)/'trusted'/'installation.json'
    report=_read_small_json(marker,'installation_manifest_invalid')
    if (type(report) is not dict or type(report.get('schema')) is not int
            or report!={'schema':1,'state':'staged','helper_sha256':expected,'controller_sid':controller_sid}):
        raise SIDLabError('installation_incomplete_or_mismatched')


def controller_sid():
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
        '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],capture_output=True,text=True,timeout=10)
    if result.returncode:raise SIDLabError('controller_identity_unavailable')
    return _sid(result.stdout.strip())


def prepare_session(controller_sid):
    """Nonprivileged owner ACL on NEW leaf only, after reviewed installation.

    Permanent controller-only lease survives crashes and uncertain cleanup.
    Never recover it automatically or edit another session's permissions.
    """
    verify_installed(controller_sid)
    control=Path(ROOT)/'control';sessions=Path(ROOT)/'sessions'
    lease=control/'active-lease.json'
    layout=RunLayout(uuid.uuid4().hex)
    with lease.open('x',encoding='ascii') as file:json.dump({'run_id':layout.run_id,'state':'reserved'},file)
    # Failure after acquiring the lease leaves it present. Operator must confirm
    # cleanup, not let a second worker access leftover same-SID data.
    if any(sessions.iterdir()):raise SIDLabError('previous_session_requires_recovery')
    directory=Path(layout.session);directory.mkdir()
    sddl=('O:'+controller_sid+'D:P(D;OICI;0xc0020;;;'+SID+')'
          '(D;OICI;0xc0000;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
          '(A;OICI;FA;;;'+controller_sid+')(A;OICI;0x13019f;;;'+SID+')')
    # Explicit inherited denies also cover group grants and implicit owner rights.
    # These do NOT enforce no-execute for a newly created protected child DACL.
    script="& {param($path,$sddl) $ErrorActionPreference='Stop';$a=New-Object Security.AccessControl.DirectorySecurity;$a.SetSecurityDescriptorSddlForm($sddl);Set-Acl -LiteralPath $path -AclObject $a}"
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script,str(directory),sddl],capture_output=True,timeout=15)
    if result.returncode:raise SIDLabError('session_owner_acl_failed')
    _no_reparse(directory)
    if not acl_matches(read_only_acl_report(directory),'session',controller_sid):
        raise SIDLabError('session_acl_not_verified')
    (directory/'access-check.txt').write_text('synthetic-access-check',encoding='ascii')
    return layout


def native_access_verified(report):
    if type(report) is not str or len(report)>8192:return False
    lines=report.splitlines()
    # Exact fixed schema rejects duplicate, extra or missing observations.
    expected={'credential_logon=1','root_identity=1',
        'environment_access=0,0','environment_access=1,5', # helper RX / no write
        'environment_access=2,0','environment_access=3,5', # Chrome RX / no write
        'environment_access=4,5','environment_access=5,5', # ONE repository probe denied
        'environment_access=6,0','environment_access=7,0', # authorized scratch read/write
        'repository_denial_verified=1'}
    return len(lines)==len(expected) and set(lines)==expected


def effective_access_check(layout,password):
    if type(layout) is not RunLayout or type(password) is not str or not password or any(c in password for c in '\r\n\0'):
        raise ValueError('invalid_environment_access_input')
    from jarvis.experimental.chromium_sid_lab import ACCOUNT
    started=time.monotonic()
    identity=controller_sid()
    verify_installed(identity)
    _verify_lease(layout)
    directory=Path(layout.session)
    if not acl_matches(read_only_acl_report(directory),'session',identity):
        raise SIDLabError('session_acl_not_verified')
    # Any other leaf is same-SID data, not an isolated concurrent session.
    if set(Path(ROOT,'sessions').iterdir())!={directory}:
        raise SIDLabError('other_session_requires_recovery')
    budget=_AuditBudget(started)
    budget.check()
    with _WindowsAccess(password) as access:
        # Keep ancestor directory handles open without SHARE_DELETE. Check parent
        # DELETE_CHILD and DACL/owner rights: a child's DACL alone cannot deny rename.
        with ExitStack() as parents:
            for ancestor in reversed(Path(REPOSITORY).parents):
                budget.check()
                info=parents.enter_context(access.inspect(ancestor))
                _require_rights(access.rights(info),forbidden=0xd0040)
            _audit_tree(Path(REPOSITORY),access,budget,'repository')
        with ExitStack() as parents:
            for ancestor in reversed(Path(ROOT).parents):
                budget.check()
                info=parents.enter_context(access.inspect(ancestor))
                _require_rights(access.rights(info),forbidden=0xd0040)
            for name,role in (('', 'root'),('trusted','trusted'),('control','control'),('sessions','sessions')):
                budget.check()
                path=Path(ROOT)/name
                with access.inspect(path) as info:
                    if not acl_matches(info.report,role,identity):raise SIDLabError('environment_acl_not_verified')
                    _require_rights(access.rights(info),forbidden=MUTATION)
            _audit_tree(Path(ROOT)/'trusted',access,budget,'trusted')
            _audit_tree(Path(ROOT)/'control',access,budget,'control')
            _audit_tree(directory,access,budget,'session')
        with access.inspect(Path(directory)/'access-check.txt') as info:
            if info.is_directory:raise SIDLabError('session_probe_not_file')
            _require_rights(access.rights(info),required=SESSION_RW,forbidden=SESSION_DENY)
    budget.check()
    # Legacy helper now checks only one explicit probe, after the complete DACL
    # audit. Its repository_denial_verified field is NOT whole-tree evidence.
    result=subprocess.run([layout.helper,'environment-access',ACCOUNT,SID,layout.helper,CHROME,
        REPOSITORY_PROBE,str(Path(layout.session)/'access-check.txt')],
        input=password+'\n1\n'+REPOSITORY_PROBE+'\n',capture_output=True,text=True,
        timeout=min(20,budget.remaining()),creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode or not native_access_verified(result.stdout):raise EffectiveAccessError(result.stdout)
    budget.check()
    # NTFS inheritance is advisory for new objects: the creator can supply a
    # protected DACL granting execute. No verified OS execution policy exists in
    # this experiment. Do not certify no-execute or launch Chromium on this basis.
    raise SIDLabError('session_execution_confinement_not_verified')


def finish_session(layout,*,job_empty,handles_closed,inspection_complete):
    if type(layout) is not RunLayout:raise ValueError('invalid_session_cleanup')
    # A same-SID process outside the Job can race any path-based preflight, even
    # when the observed Job is empty. There is no handle-relative deleter here.
    # Never inspect then rmtree/unlink: retain BOTH data and reservation, always.
    return False


def _verify_lease(layout):
    path=Path(ROOT)/'control'/'active-lease.json'
    _no_reparse(path)
    report=_read_small_json(path,'session_lease_invalid')
    if report!={'run_id':layout.run_id,'state':'reserved'}:
        raise SIDLabError('session_lease_mismatch')


def _read_small_json(path,error):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate_json_field')
            result[key]=value
        return result
    try:
        with path.open(encoding='ascii') as file:text=file.read(1025)
        if len(text)>1024:raise ValueError('json_too_large')
        return json.loads(text,object_pairs_hook=unique)
    except (ValueError,UnicodeError):raise SIDLabError(error) from None


def _require_rights(granted,*,required=0,forbidden=0):
    if type(granted) is not int or not 0<=granted<=0x1f01ff:
        raise SIDLabError('effective_rights_invalid')
    if granted&required!=required or granted&forbidden:
        raise SIDLabError('effective_rights_not_verified')


class _AuditBudget:
    def __init__(self,started):self.started=started;self.entries=0
    def remaining(self):
        remaining=AUDIT_SECONDS-(time.monotonic()-self.started)
        if remaining<=0:raise SIDLabError('repository_audit_timeout')
        return remaining
    def check(self):self.remaining()
    def visit(self):
        self.check();self.entries+=1
        if self.entries>AUDIT_LIMIT:raise SIDLabError('repository_audit_limit')


def _audit_tree(path,access,budget,role):
    """Stream EVERY descriptor, including directories; unknown/reparse fails.

    Directory handles pin traversed ancestors while scandir runs. This is a
    point-in-time DACL audit, not a freeze against future privileged changes.
    """
    budget.visit()
    with access.inspect(path) as info:
        granted=access.rights(info)
        if role in {'repository','control'}:
            _require_rights(granted,forbidden=READ_CONTENT|MUTATION|(0 if info.is_directory else EXECUTE))
        elif role=='trusted':
            _require_rights(granted,required=RX,forbidden=MUTATION)
        elif role=='session':
            # FILE_EXECUTE and FILE_TRAVERSE share a bit; SeChangeNotifyPrivilege
            # can bypass directory traversal denial, never file-execute denial.
            _require_rights(granted,required=SESSION_RW,forbidden=SESSION_DENY)
        else:raise ValueError('invalid_audit_role')
        if info.is_directory:
            with os.scandir(path) as entries:
                for entry in entries:
                    _audit_tree(Path(entry.path),access,budget,role)


@dataclass(frozen=True,slots=True)
class _ObjectSecurity:
    report:dict
    descriptor:bytes
    is_directory:bool


def read_only_acl_report(path):
    # No PowerShell process per file; retain ACE flags/order for strict checks.
    with _WindowsAccess() as access:
        with access.inspect(path) as info:return info.report


class _WindowsAccess:
    """Read-only local Win32 descriptors and AccessCheck with a real logon token.

    Never impersonates the controller thread or modifies privileges/ACLs. Only
    simple allow/deny ACEs are supported; conditional/object ACEs fail closed.
    Cached results are keyed by complete descriptor bytes within ONE token/audit.
    """
    def __init__(self,password=None):
        if os.name!='nt':raise SIDLabError('windows_required')
        import ctypes as c
        from ctypes import wintypes as w
        self.c=c;self.w=w;self.password=password;self.handles=[];self.cache={};self.volumes=set()
        self.kernel=c.WinDLL('kernel32',use_last_error=True)
        self.adv=c.WinDLL('advapi32',use_last_error=True)
        def api(dll,name,result,*args):
            fn=getattr(dll,name);fn.restype=result;fn.argtypes=list(args);return fn
        pointer=c.c_void_p;dword=w.DWORD;pdword=c.POINTER(dword);ppointer=c.POINTER(pointer)
        self.close=api(self.kernel,'CloseHandle',w.BOOL,w.HANDLE)
        self.free=api(self.kernel,'LocalFree',pointer,pointer)
        self.create=api(self.kernel,'CreateFileW',w.HANDLE,w.LPCWSTR,dword,dword,pointer,dword,dword,w.HANDLE)
        self.final_path=api(self.kernel,'GetFinalPathNameByHandleW',dword,w.HANDLE,w.LPWSTR,dword,dword)
        self.file_info=api(self.kernel,'GetFileInformationByHandleEx',w.BOOL,w.HANDLE,c.c_int,pointer,dword)
        self.volume=api(self.kernel,'GetVolumeInformationW',w.BOOL,w.LPCWSTR,w.LPWSTR,dword,pdword,pdword,pdword,w.LPWSTR,dword)
        self.security=api(self.adv,'GetSecurityInfo',dword,w.HANDLE,c.c_int,dword,ppointer,ppointer,ppointer,ppointer,ppointer)
        self.sd_length=api(self.adv,'GetSecurityDescriptorLength',dword,pointer)
        self.sd_control=api(self.adv,'GetSecurityDescriptorControl',w.BOOL,pointer,c.POINTER(w.WORD),pdword)
        self.get_ace=api(self.adv,'GetAce',w.BOOL,pointer,dword,ppointer)
        self.sid_text=api(self.adv,'ConvertSidToStringSidW',w.BOOL,pointer,ppointer)
        self.logon=api(self.adv,'LogonUserW',w.BOOL,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,dword,dword,ppointer)
        self.duplicate=api(self.adv,'DuplicateToken',w.BOOL,w.HANDLE,c.c_int,ppointer)
        self.token_info=api(self.adv,'GetTokenInformation',w.BOOL,w.HANDLE,c.c_int,pointer,dword,pdword)
        self.privilege=api(self.adv,'LookupPrivilegeValueW',w.BOOL,w.LPCWSTR,w.LPCWSTR,pointer)
        self.access_check=api(self.adv,'AccessCheck',w.BOOL,pointer,w.HANDLE,dword,pointer,pointer,pdword,pdword,c.POINTER(w.BOOL))

    def _require(self,ok,stage):
        if not ok:raise SIDLabError(stage)  # Never include OS text, paths or secrets.

    def _close(self,handle):self._require(self.close(handle),'audit_handle_close_failed')

    def __enter__(self):
        if self.password is None:return self
        from jarvis.experimental.chromium_sid_lab import ACCOUNT
        c=self.c;primary=c.c_void_p();token=c.c_void_p()
        try:
            self._require(self.logon(ACCOUNT,'.',self.password,2,0,c.byref(primary)),'credential_logon_failed')
            self.handles.append(primary)
            self._verify_identity(primary)
            self._require(self.duplicate(primary,2,c.byref(token)),'audit_token_duplicate_failed')
            self.handles.append(token);self.token=token
            return self
        except BaseException:
            self.__exit__(None,None,None);raise
        finally:self.password=None

    def __exit__(self,*unused):
        failures=[]
        for handle in reversed(self.handles):
            if not self.close(handle):failures.append(True)
        self.handles.clear();self.cache.clear();self.password=None
        if hasattr(self,'token'):del self.token
        if failures:raise SIDLabError('audit_token_close_failed')

    def _token_buffer(self,token,kind):
        c=self.c;size=self.w.DWORD()
        ok=self.token_info(token,kind,None,0,c.byref(size))
        self._require(not ok and c.get_last_error()==122 and 0<size.value<=65536,'audit_token_info_failed')
        buffer=c.create_string_buffer(size.value)
        self._require(self.token_info(token,kind,buffer,size,c.byref(size)),'audit_token_info_failed')
        return buffer

    def _sid_text(self,sid):
        c=self.c;text=c.c_void_p()
        self._require(self.sid_text(sid,c.byref(text)),'audit_sid_failed')
        try:return c.wstring_at(text)
        finally:self._require(not self.free(text),'audit_descriptor_free_failed')

    def _verify_identity(self,token):
        c=self.c;w=self.w
        class SidAttributes(c.Structure):_fields_=[('sid',c.c_void_p),('attributes',w.DWORD)]
        class Groups(c.Structure):_fields_=[('count',w.DWORD),('items',SidAttributes*1)]
        class Luid(c.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
        class Privilege(c.Structure):_fields_=[('luid',Luid),('attributes',w.DWORD)]
        class Privileges(c.Structure):_fields_=[('count',w.DWORD),('items',Privilege*1)]
        user=self._token_buffer(token,1)
        self._require(self._sid_text(SidAttributes.from_buffer(user).sid)==SID,'root_identity_not_verified')
        groups=self._token_buffer(token,2);count=w.DWORD.from_buffer(groups).value;offset=Groups.items.offset
        self._require(offset+count*c.sizeof(SidAttributes)<=len(groups),'audit_token_groups_invalid')
        for index in range(count):
            group=SidAttributes.from_buffer(groups,offset+index*c.sizeof(SidAttributes))
            self._require(self._sid_text(group.sid)!='S-1-5-32-544','worker_admin_group_forbidden')
        privileges=self._token_buffer(token,3);count=w.DWORD.from_buffer(privileges).value;offset=Privileges.items.offset
        self._require(offset+count*c.sizeof(Privilege)<=len(privileges),'audit_token_privileges_invalid')
        present={(Privilege.from_buffer(privileges,offset+i*c.sizeof(Privilege)).luid.low,
                  Privilege.from_buffer(privileges,offset+i*c.sizeof(Privilege)).luid.high) for i in range(count)}
        for name in ('SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege',
                     'SeImpersonatePrivilege','SeTcbPrivilege','SeSecurityPrivilege','SeCreateTokenPrivilege',
                     'SeAssignPrimaryTokenPrivilege','SeLoadDriverPrivilege','SeManageVolumePrivilege','SeRelabelPrivilege'):
            luid=Luid();self._require(self.privilege(None,name,c.byref(luid)),'audit_privilege_lookup_failed')
            # Reject even disabled privileges; the worker could enable them later.
            self._require((luid.low,luid.high) not in present,'worker_privilege_forbidden')

    @contextmanager
    def inspect(self,path):
        c=self.c;w=self.w;path=os.path.abspath(path)
        if any(ch in path for ch in '\r\n\0"') or not re.match(r'^[A-Za-z]:\\',path):
            raise SIDLabError('invalid_repository_audit_path')
        drive=Path(path).anchor
        if drive not in self.volumes:
            fs=c.create_unicode_buffer(32)
            self._require(self.volume(drive,None,0,None,None,None,fs,len(fs)) and fs.value=='NTFS','local_ntfs_required')
            self.volumes.add(drive)
        # READ_CONTROL, OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
        # No SHARE_DELETE: keep this object's identity pinned during inspection.
        handle=self.create(path,0x20000,3,None,3,0x02200000,None)
        self._require(handle not in (None,c.c_void_p(-1).value),'audit_object_open_failed')
        try:
            final=c.create_unicode_buffer(32768)
            length=self.final_path(handle,final,len(final),0)
            self._require(0<length<len(final) and final.value.startswith('\\\\?\\')
                          and os.path.normcase(final.value[4:])==os.path.normcase(path),'audit_object_identity_failed')
            tag=(w.DWORD*2)()
            self._require(self.file_info(handle,9,tag,c.sizeof(tag)),'audit_object_info_failed')
            self._require(not tag[0]&0x400,'environment_reparse_forbidden')
            owner=c.c_void_p();group=c.c_void_p();dacl=c.c_void_p();sd=c.c_void_p()
            code=self.security(handle,1,7,c.byref(owner),c.byref(group),c.byref(dacl),None,c.byref(sd))
            self._require(code==0,'audit_descriptor_unavailable')
            try:
                self._require(bool(owner.value and group.value and dacl.value),'audit_descriptor_incomplete')
                control=w.WORD();revision=w.DWORD()
                self._require(self.sd_control(sd,c.byref(control),c.byref(revision)),'audit_descriptor_invalid')
                aces=[]
                count=w.WORD.from_address(dacl.value+4).value
                for index in range(count):
                    ace=c.c_void_p();self._require(self.get_ace(dacl,index,c.byref(ace)),'audit_ace_invalid')
                    header=(c.c_ubyte*4).from_address(ace.value)
                    self._require(header[0] in (0,1),'audit_ace_unsupported')
                    aces.append(dict(sid=self._sid_text(ace.value+8),mask=w.DWORD.from_address(ace.value+4).value,
                                     qualifier='AccessAllowed' if header[0]==0 else 'AccessDenied',flags=header[1]))
                report=dict(owner=self._sid_text(owner),protected=bool(control.value&0x1000),aces=aces)
                size=self.sd_length(sd)
                self._require(0<size<=65536,'audit_descriptor_invalid')
                yield _ObjectSecurity(report,c.string_at(sd,size),bool(tag[0]&0x10))
            finally:self._require(not self.free(sd),'audit_descriptor_free_failed')
        finally:self._close(handle)

    def rights(self,info):
        if not hasattr(self,'token'):raise SIDLabError('audit_logon_required')
        key=info.descriptor
        if key in self.cache:return self.cache[key]
        c=self.c;w=self.w
        # File and directory generic mappings share bit values, with different
        # meanings (WRITE_DATA/ADD_FILE, APPEND_DATA/ADD_SUBDIRECTORY).
        mapping=(w.DWORD*4)(0x120089,0x120116,0x1200a0,0x1f01ff)
        descriptor=c.create_string_buffer(key);privileges=c.create_string_buffer(65536)
        size=w.DWORD(len(privileges));granted=w.DWORD();status=w.BOOL()
        self._require(self.access_check(descriptor,self.token,0x02000000,mapping,privileges,c.byref(size),
                                       c.byref(granted),c.byref(status)),'audit_access_check_failed')
        if not status.value:
            self._require(c.get_last_error()==5,'audit_access_status_invalid');result=0
        else:result=granted.value
        if len(self.cache)>=4096:self.cache.clear()
        self.cache[key]=result
        return result
