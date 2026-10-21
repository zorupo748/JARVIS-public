"""Reproducible staging ONLY, no installed runtime or ACL changes.

Workspace staging is not secure installation. Administrative review must copy
to protected Program Files and validate protected parent chain/ACL and hashes.
Local hashes prove integrity against an approved manifest, not vendor identity.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil

from jarvis.experimental.chromium_sid_lab import SID

FILES=("chrome.exe","chrome.dll","chrome_elf.dll","chrome_wer.dll","icudtl.dat","resources.pak",
       "chrome_100_percent.pak","chrome_200_percent.pak","v8_context_snapshot.bin","D3DCompiler_47.dll",
       "dxcompiler.dll","dxil.dll","libEGL.dll","libGLESv2.dll","vulkan-1.dll","vk_swiftshader.dll",
       "vk_swiftshader_icd.json","locales/en-US.pak")
INSTALL_ROOT=r'C:\Program Files\JARVISBrowserLab'


@dataclass(frozen=True,slots=True)
class RuntimeFile:
    name:str
    size:int
    sha256:str


def _plain_file(path):
    if not path.is_file() or path.is_symlink():raise ValueError('runtime_file_invalid')
    for component in (path,*path.parents):
        if component.is_symlink() or getattr(component.stat(),'st_file_attributes',0)&0x400:
            raise ValueError('runtime_reparse_point')


def digest(path):
    _plain_file(path)
    with path.open('rb') as stream:
        result=hashlib.file_digest(stream,'sha256').hexdigest()
    return result


def stage_runtime(source,destination):
    source=Path(source);destination=Path(destination)
    if not source.is_absolute() or not destination.is_absolute() or destination.exists():
        raise ValueError('runtime_staging_path_invalid')
    manifests=tuple(p.name for p in source.glob('*.manifest'))
    if not manifests or any(re.fullmatch(r'[0-9]+(?:\.[0-9]+)+\.manifest',name) is None for name in manifests):
        raise ValueError('runtime_manifest_invalid')
    names=FILES+tuple(sorted(manifests))
    records=tuple(RuntimeFile(name,(source/name).stat().st_size,digest(source/name)) for name in names)
    destination.mkdir(parents=False)
    for record in records:
        target=destination/record.name;target.parent.mkdir(exist_ok=True)
        shutil.copyfile(source/record.name,target)
        if target.stat().st_size!=record.size or digest(target)!=record.sha256:
            raise ValueError('runtime_copy_integrity_failed')
    return records


def validate_runtime(directory,records):
    if type(records) is not tuple or not records or any(type(r) is not RuntimeFile for r in records):return False
    if len({r.name for r in records})!=len(records):return False
    if not set(FILES).issubset({r.name for r in records}) or not any(r.name.endswith('.manifest') for r in records):return False
    for record in records:
        if (record.name not in FILES and re.fullmatch(r'[0-9]+(?:\.[0-9]+)+\.manifest',record.name) is None):return False
        if type(record.size) is not int or record.size<=0 or re.fullmatch(r'[a-f0-9]{64}',record.sha256) is None:return False
    try:
        directory=Path(directory)
        actual={p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
        if actual!={r.name for r in records}:return False
        return all((directory/r.name).stat().st_size==r.size and digest(directory/r.name)==r.sha256 for r in records)
    except (OSError,ValueError):return False


def read_only_acl_report(path):
    """Read actual Windows descriptor, not an assertion of effective access."""
    import json,subprocess
    if os.name!='nt':raise RuntimeError('windows_required')
    path=str(Path(path))
    if any(c in path for c in '\r\n\0\"'):raise ValueError('invalid_acl_path')
    script="""& {param($path) $ErrorActionPreference='Stop';$a=Get-Acl -LiteralPath $path;
$s=New-Object Security.AccessControl.RawSecurityDescriptor($a.Sddl)
@{owner=$s.Owner.Value;protected=$a.AreAccessRulesProtected;sddl=$a.Sddl;
aces=@($s.DiscretionaryAcl|ForEach-Object {@{sid=$_.SecurityIdentifier.Value;mask=[long]$_.AccessMask;qualifier=[string]$_.AceQualifier}})}|ConvertTo-Json -Depth 5 -Compress} """
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script,path],capture_output=True,text=True,timeout=15)
    if result.returncode:raise RuntimeError('acl_inspection_failed')
    return json.loads(result.stdout)


def validate_runtime_acl(report):
    """Strict expected protected DACL; not a substitute for token AccessCheck."""
    if (type(report) is not dict or report.get('protected') is not True
            or report.get('owner') not in {'S-1-5-18','S-1-5-32-544'}
            or type(report.get('aces')) is not list or len(report['aces'])!=3):return False
    seen=set()
    for ace in report['aces']:
        if type(ace) is not dict or ace.get('qualifier')!='AccessAllowed' or type(ace.get('mask')) is not int:return False
        sid=ace.get('sid');mask=ace['mask']
        if sid in seen:return False
        seen.add(sid)
        if sid==SID:
            if mask!=0x1200a9:return False
        elif sid in {'S-1-5-18','S-1-5-32-544'}:
            if mask!=0x1f01ff:return False
        else:return False
    return seen=={'S-1-5-18','S-1-5-32-544',SID}


def approved_runtime_sddl():
    # SYSTEM owns executables; admin operators provision them; worker has RX
    # only. No user/controller/agent has write/delete/ownership grants.
    return 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;'+SID+')'


def privileged_review_spec(records):
    """DATA ONLY: no privileged script execution or implicit installation."""
    return dict(destination=INSTALL_ROOT,worker_sid=SID,owner='Administrators',
                executable_sddl=approved_runtime_sddl(),inheritance='disabled',
                source_hashes=records,profile_separate=True,
                require_parent_chain_protected=True,require_worker_cannot_write_or_replace=True)
