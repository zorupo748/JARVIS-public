"""Mocked security tests plus read-only controller Win32 checks; no ACL writes."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from jarvis.experimental import browser_run_environment as env
from jarvis.experimental.chromium_sid_lab import parse_chromium_report,classify_stderr
from jarvis.experimental import chromium_sid_lab as chromium
from jarvis.experimental.sid_firewall_lab import SIDLabError

CONTROLLER='S-1-5-21-2213057978-1848420950-3946800094-1001'
VALID_NATIVE='\n'.join(['credential_logon=1','root_identity=1']+
    ['environment_access='+str(i)+','+str(v) for i,v in enumerate((0,5,0,5,5,5,0,0))]+
    ['repository_denial_verified=1'])


def acl_report(role,*,directory=True):
    flags=3 if directory else 0
    aces=[]
    if role=='session':
        aces=[dict(sid=env.SID,mask=env.SESSION_DENY,qualifier='AccessDenied',flags=flags),
              dict(sid=env.OWNER_RIGHTS,mask=0xc0000,qualifier='AccessDenied',flags=flags)]
    aces += [dict(sid=sid,mask=mask,qualifier='AccessAllowed',flags=flags)
             for sid,mask in env.expected_acl(role,CONTROLLER).items()]
    return dict(owner=CONTROLLER if role=='session' else 'S-1-5-32-544',protected=True,aces=aces)


class FakeAccess:
    """Synthetic token/descriptor backend; no Win32 security calls."""
    def __init__(self,grants=None,reports=None):
        self.grants=grants or {};self.reports=reports or {};self.visited=[];self.closed=False
    def __enter__(self):return self
    def __exit__(self,*unused):self.closed=True
    @contextmanager
    def inspect(self,path):
        path=Path(path);self.visited.append(path)
        if path.is_symlink():raise SIDLabError('environment_reparse_forbidden')
        yield env._ObjectSecurity(self.reports.get(path,{}),str(path).encode(),path.is_dir())
    def rights(self,info):return self.grants.get(Path(info.descriptor.decode()),0)


class RunEnvironmentTests(unittest.TestCase):
    def test_exact_paths_outside_repository(self):
        layout=env.RunLayout('a'*32)
        self.assertTrue(env.allowed_paths(layout.helper,env.CHROME,layout.session))
        self.assertNotIn('E:\\JARVIS',layout.session)
        for session in (layout.session+'\\..',layout.session+':secret','E:\\JARVIS\\profile',layout.session.lower()):
            with self.subTest(session=session):self.assertFalse(env.allowed_paths(layout.helper,env.CHROME,session))
        self.assertFalse(env.allowed_paths('E:\\JARVIS\\launcher.exe',env.CHROME,layout.session))

    def report(self,role):
        return acl_report(role)

    def test_role_acls_no_worker_write_to_trusted_or_control(self):
        for role in ('root','trusted','control','sessions'):
            self.assertTrue(env.acl_matches(self.report(role),role,CONTROLLER))
        self.assertNotIn(env.SID,env.expected_acl('control',CONTROLLER))
        self.assertEqual(env.expected_acl('trusted',CONTROLLER)[env.SID],0x1200a9)
        report=self.report('trusted');report['aces'][-2]['mask']=0x1f01ff
        self.assertFalse(env.acl_matches(report,'trusted',CONTROLLER))
        report=self.report('trusted');report['protected']=False
        self.assertFalse(env.acl_matches(report,'trusted',CONTROLLER))

    def test_effective_token_access_must_include_repository_denial(self):
        lines=['credential_logon=1','root_identity=1']+['environment_access='+str(i)+','+str(v)
            for i,v in enumerate((0,5,0,5,5,5,0,0))]
        lines.append('repository_denial_verified=1')
        self.assertTrue(env.native_access_verified('\n'.join(lines)))
        for index in range(2,len(lines)-1):
            changed=list(lines);changed[index]=changed[index].rsplit(',',1)[0]+',13'
            self.assertFalse(env.native_access_verified('\n'.join(changed)))
        self.assertFalse(env.native_access_verified('\n'.join(lines+[lines[0]])))
        self.assertFalse(env.native_access_verified('\n'.join(lines).replace('environment_access=4,5','environment_access=4,0')))
        self.assertFalse(env.native_access_verified('\n'.join(lines).replace('repository_denial_verified=1','repository_denial_verified=0')))

    def test_inspection_failure_has_distinct_stage_and_no_escape_claim(self):
        result=parse_chromium_report('chromium_report=1\nprocess=123,unknown,0,0,5\ninspection_diag=123,token_open,5\n'
            'network_process_count=2\ndiag=wait_timeout,0\n')
        self.assertEqual(result.inspection_diagnostics,((123,'token_open',5),))
        self.assertEqual(result.observed_network_process_count,2)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.status,'inconclusive')

    def test_stderr_categories_are_bounded_and_never_export_text(self):
        self.assertEqual(classify_stderr('Network service crashed DO_NOT_LEAK /private/profile'),('network_service_crash_reported',))
        self.assertNotIn('DO_NOT_LEAK',repr(classify_stderr('Access is denied DO_NOT_LEAK')))
        self.assertEqual(classify_stderr('x'*65537),('stderr_truncated',))

    def test_effective_access_errors_preserve_codes_without_raw_messages(self):
        error=env.EffectiveAccessError('diag=credential_logon,1326\nenvironment_access=4,0\nrepository_denial_verified=0\nDO_NOT_LEAK')
        self.assertEqual(error.facts,(('credential_logon',0,1326),('access',4,0),('repository_denial_verified',0,0)))
        self.assertNotIn('DO_NOT_LEAK',str(error))

    def test_uncertain_cleanup_keeps_persistent_lease(self):
        with tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root):
            control=Path(root)/'control';control.mkdir();lease=control/'active-lease.json';lease.write_text('{}')
            layout=env.RunLayout('a'*32)
            self.assertFalse(env.finish_session(layout,job_empty=True,handles_closed=False,inspection_complete=True))
            self.assertTrue(lease.exists())

    def test_confirmed_cleanup_also_keeps_data_and_reservation(self):
        with tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root):
            control=Path(root)/'control';control.mkdir();sessions=Path(root)/'sessions';sessions.mkdir()
            layout=env.RunLayout('a'*32);directory=Path(layout.session);directory.mkdir()
            (directory/'fixture.txt').write_text('synthetic')
            lease=control/'active-lease.json';lease.write_text(json.dumps({'run_id':layout.run_id}))
            with patch.object(shutil,'rmtree') as remove,patch.object(Path,'unlink') as unlink:
                self.assertFalse(env.finish_session(layout,job_empty=True,handles_closed=True,inspection_complete=True))
                remove.assert_not_called();unlink.assert_not_called()
            self.assertTrue(directory.exists());self.assertTrue(lease.exists())
            self.assertEqual((directory/'fixture.txt').read_text(),'synthetic')

    def test_wrong_session_lease_does_not_delete_files(self):
        with tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root):
            control=Path(root)/'control';control.mkdir();sessions=Path(root)/'sessions';sessions.mkdir()
            layout=env.RunLayout('a'*32);directory=Path(layout.session);directory.mkdir()
            (control/'active-lease.json').write_text(json.dumps({'run_id':'b'*32}))
            self.assertFalse(env.finish_session(layout,job_empty=True,handles_closed=True,inspection_complete=True))
            self.assertTrue(directory.exists())

    def test_previous_or_duplicate_session_blocks_creation(self):
        with tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root),patch.object(env,'verify_installed'):
            control=Path(root)/'control';control.mkdir();sessions=Path(root)/'sessions';sessions.mkdir();(sessions/'previous').mkdir()
            with self.assertRaises(SIDLabError):env.prepare_session(CONTROLLER)
            self.assertTrue((control/'active-lease.json').exists())
            with self.assertRaises(FileExistsError):env.prepare_session(CONTROLLER)

    def test_session_acl_owner_flags_denies_and_order_must_match(self):
        self.assertTrue(env.acl_matches(acl_report('session'),'session',CONTROLLER))
        for change in ('owner','inheritance','inherit_only','execute','owner_deny','order','duplicate'):
            report=acl_report('session')
            if change=='owner':report['owner']=env.SID
            elif change=='inheritance':report['protected']=False
            elif change=='inherit_only':report['aces'][0]['flags']=11
            elif change=='execute':report['aces'][-1]['mask']|=env.EXECUTE
            elif change=='owner_deny':report['aces'].pop(1)
            elif change=='order':report['aces']=report['aces'][2:]+report['aces'][:2]
            else:report['aces'].append(report['aces'][0])
            with self.subTest(change=change):self.assertFalse(env.acl_matches(report,'session',CONTROLLER))
        self.assertFalse(env.acl_matches(acl_report('trusted'),'trusted',CONTROLLER,directory=False))
        self.assertTrue(env.acl_matches(acl_report('trusted',directory=False),'trusted',CONTROLLER,directory=False))

    def test_worker_cannot_be_controller(self):
        with self.assertRaises(SIDLabError):env.expected_acl('session',env.SID)

    def test_prepare_checks_acl_after_setting_and_retains_lease_on_failure(self):
        for failure in ('set_failed','wrong_owner','missing_deny','correct'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root),patch.object(env,'verify_installed'):
                Path(root,'control').mkdir();Path(root,'sessions').mkdir()
                report=acl_report('session')
                if failure=='wrong_owner':report['owner']=env.SID
                if failure=='missing_deny':report['aces'].pop(0)
                with patch.object(env.subprocess,'run',return_value=Mock(returncode=int(failure=='set_failed'))) as execute,patch.object(env,'read_only_acl_report',return_value=report) as inspect:
                    if failure=='correct':
                        layout=env.prepare_session(CONTROLLER)
                        self.assertTrue(Path(layout.session,'access-check.txt').is_file())
                        inspect.assert_called_once_with(Path(layout.session))
                    else:
                        with self.assertRaises(SIDLabError):env.prepare_session(CONTROLLER)
                        self.assertFalse(any(Path(root,'sessions').rglob('access-check.txt')))
                    self.assertIn('(D;OICI;0xc0020;;;'+env.SID+')',execute.call_args.args[0][-1])
                    self.assertIn('(D;OICI;0xc0000;;;OW)',execute.call_args.args[0][-1])
                self.assertTrue(Path(root,'control','active-lease.json').is_file())

    def test_cleanup_never_traverses_unverified_or_racing_paths(self):
        with patch.object(env,'_no_reparse',side_effect=AssertionError('racing path')),patch.object(Path,'resolve',side_effect=AssertionError('unverified resolve')),patch.object(Path,'rglob',side_effect=AssertionError('unverified traversal')),patch.object(Path,'unlink',side_effect=AssertionError('unlink')),patch.object(shutil,'rmtree',side_effect=AssertionError('recursive delete')):
            for job,handles,inspection in ((True,True,True),(False,True,True),(True,False,True),(True,True,False)):
                self.assertFalse(env.finish_session(env.RunLayout('a'*32),job_empty=job,handles_closed=handles,inspection_complete=inspection))

    def test_every_file_and_directory_checked_without_rglob_or_ancestor_rescan(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);(root/'empty').mkdir();(root/'nested').mkdir();(root/'nested'/'file').write_text('synthetic')
            access=FakeAccess();budget=env._AuditBudget(time.monotonic())
            with patch.object(Path,'rglob',side_effect=AssertionError('old scan')),patch.object(env,'_no_reparse',side_effect=AssertionError('ancestor rescan')):
                env._audit_tree(root,access,budget,'repository')
            self.assertEqual(set(access.visited),{root,root/'empty',root/'nested',root/'nested'/'file'})
            self.assertEqual(budget.entries,4)

    def test_repository_partial_rights_and_directory_mutations_deny(self):
        # GENERIC_READ or GENERIC_WRITE denial cannot prove denial of these bits.
        for right in (1,2,4,8,0x10,0x40,0x80,0x100,0x10000,0x20000,0x40000,0x80000):
            with self.subTest(right=right),tempfile.TemporaryDirectory() as root:
                root=Path(root);(root/'directory').mkdir()
                with self.assertRaises(SIDLabError):
                    env._audit_tree(root,FakeAccess({root/'directory':right}),env._AuditBudget(time.monotonic()),'repository')

    def test_incomplete_or_late_audit_never_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);(root/'child').write_text('synthetic')
            for maximum in (0,1):
                with self.subTest(maximum=maximum),patch.object(env,'AUDIT_LIMIT',maximum),self.assertRaisesRegex(SIDLabError,'repository_audit_limit'):
                    env._audit_tree(root,FakeAccess(),env._AuditBudget(time.monotonic()),'repository')
            with patch.object(env,'AUDIT_SECONDS',1),self.assertRaisesRegex(SIDLabError,'repository_audit_timeout'):
                env._audit_tree(root,FakeAccess(),env._AuditBudget(time.monotonic()-2),'repository')
            with patch.object(os,'scandir',side_effect=PermissionError),self.assertRaises(PermissionError):
                env._audit_tree(root,FakeAccess(),env._AuditBudget(time.monotonic()),'repository')

    def test_file_execute_and_invalid_masks_reject(self):
        for mask in (-1,True,0x80000000,'0',env.SESSION_RW|env.EXECUTE,env.SESSION_RW|0x40000):
            with self.subTest(mask=mask),self.assertRaises(SIDLabError):
                env._require_rights(mask,required=env.SESSION_RW,forbidden=env.SESSION_DENY)

    @contextmanager
    def effective_fixture(self):
        with tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root),patch.object(env,'REPOSITORY',str(Path(root,'repo'))),patch.object(env,'REPOSITORY_PROBE',str(Path(root,'repo','probe.py'))):
            root=Path(root);(root/'repo').mkdir();(root/'repo'/'probe.py').write_text('synthetic')
            for name in ('trusted','control','sessions'):(root/name).mkdir()
            layout=env.RunLayout('a'*32);directory=Path(layout.session);directory.mkdir();(directory/'access-check.txt').write_text('synthetic')
            (root/'control'/'active-lease.json').write_text(json.dumps({'run_id':layout.run_id,'state':'reserved'}))
            reports={root:acl_report('root'),root/'trusted':acl_report('trusted'),root/'control':acl_report('control'),root/'sessions':acl_report('sessions')}
            access=FakeAccess({root/'trusted':env.RX,directory:env.SESSION_RW,directory/'access-check.txt':env.SESSION_RW},reports)
            with patch.object(env,'controller_sid',return_value=CONTROLLER),patch.object(env,'verify_installed'),patch.object(env,'read_only_acl_report',return_value=acl_report('session')),patch.object(env,'_WindowsAccess',return_value=access),patch.object(env.subprocess,'run',return_value=Mock(returncode=0,stdout=VALID_NATIVE)) as execute:
                yield root,layout,access,execute

    def test_parent_delete_child_blocks_before_legacy_helper(self):
        with self.effective_fixture() as (root,layout,access,execute):
            access.grants[root]=0x40
            with self.assertRaisesRegex(SIDLabError,'effective_rights_not_verified'):env.effective_access_check(layout,'DO_NOT_LEAK')
            execute.assert_not_called();self.assertTrue(access.closed)

    def test_trusted_control_and_session_unsafe_rights_block(self):
        for relative,grant in (('trusted',env.RX|2),('control',0x40),('sessions',0x40000),('session',env.SESSION_RW|env.EXECUTE),('session',env.SESSION_RW&~2)):
            with self.subTest(relative=relative,grant=grant),self.effective_fixture() as (root,layout,access,execute):
                path=Path(layout.session) if relative=='session' else root/relative
                access.grants[path]=grant
                with self.assertRaises(SIDLabError):env.effective_access_check(layout,'DO_NOT_LEAK')
                execute.assert_not_called()

    def test_other_sessions_or_mismatched_lease_block(self):
        for failure in ('sibling','wrong_lease','oversized_lease'):
            with self.subTest(failure=failure),self.effective_fixture() as (root,layout,access,execute):
                lease=root/'control'/'active-lease.json'
                if failure=='sibling':(root/'sessions'/'b').mkdir()  # Any extra leaf blocks.
                elif failure=='wrong_lease':lease.write_text('{}')
                else:lease.write_text('x'*1025)
                with self.assertRaises(SIDLabError):env.effective_access_check(layout,'DO_NOT_LEAK')
                execute.assert_not_called();self.assertTrue(lease.exists())

    def test_complete_acl_audit_and_native_probe_still_do_not_prove_future_noexecute(self):
        with self.effective_fixture() as (root,layout,access,execute):
            with self.assertRaisesRegex(SIDLabError,'session_execution_confinement_not_verified'):env.effective_access_check(layout,'DO_NOT_LEAK')
            self.assertIn(root/'repo',access.visited);self.assertIn(root/'repo'/'probe.py',access.visited)
            self.assertIn(Path(layout.session,'access-check.txt'),access.visited)
            arguments=execute.call_args
            self.assertEqual(arguments.kwargs['input'],'DO_NOT_LEAK\n1\n'+env.REPOSITORY_PROBE+'\n')
            self.assertNotIn('DO_NOT_LEAK',repr(arguments.args))
            self.assertLessEqual(arguments.kwargs['timeout'],20)
            self.assertTrue((root/'control'/'active-lease.json').exists())

    def test_legacy_partial_or_error_report_is_not_accepted(self):
        for stdout,code in ((VALID_NATIVE,1),(VALID_NATIVE.replace('environment_access=7,0','environment_access=7,5'),0),('DO_NOT_LEAK',0)):
            with self.subTest(code=code),self.effective_fixture() as (root,layout,access,execute):
                execute.return_value=Mock(returncode=code,stdout=stdout)
                with self.assertRaises(env.EffectiveAccessError) as caught:env.effective_access_check(layout,'transient')
                self.assertNotIn('DO_NOT_LEAK',str(caught.exception))

    def test_failed_effective_access_never_launches_chromium_or_creates_profile(self):
        with tempfile.TemporaryDirectory() as root,patch.object(chromium,'preflight'),patch.object(env,'allowed_paths',return_value=True),patch.object(env,'verify_installed'),patch.object(env,'controller_sid',return_value=CONTROLLER),patch.object(env,'RunLayout'),patch.object(env,'effective_access_check',side_effect=SIDLabError('session_execution_confinement_not_verified')),patch.object(chromium.subprocess,'run') as execute:
            with self.assertRaises(SIDLabError):chromium.run_chromium_probe(str(Path(root,'helper.exe')),env.CHROME,root,password='transient',guard=chromium.RuleLifetimeGuard())
            execute.assert_not_called();self.assertFalse(Path(root,'profile').exists())

    def test_partial_install_or_unapproved_manifest_blocks_verification(self):
        for state in ('missing','truncated','duplicate','boolean_schema','wrong_hash','wrong_controller','incomplete','correct'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as root,patch.object(env,'ROOT',root):
                root=Path(root)
                for name in ('trusted','control','sessions'):(root/name).mkdir()
                (root/'trusted'/'launcher.exe').write_bytes(b'synthetic')
                helper_hash=env.digest(root/'trusted'/'launcher.exe')
                (root/'trusted'/'launcher.sha256').write_text(helper_hash)
                manifest={'schema':1,'state':'staged','helper_sha256':helper_hash,'controller_sid':CONTROLLER}
                if state=='wrong_hash':manifest['helper_sha256']='0'*64
                if state=='wrong_controller':manifest['controller_sid']=env.SID
                if state=='incomplete':manifest['state']='pending'
                if state=='boolean_schema':manifest['schema']=True
                if state!='missing':
                    text='{' if state=='truncated' else json.dumps(manifest)
                    if state=='duplicate':text=text[:-1]+',"schema":1}'
                    (root/'trusted'/'installation.json').write_text(text)
                def report(path):
                    path=Path(path);role='root' if path==root else path.name if path.is_dir() else 'trusted'
                    return acl_report(role,directory=path.is_dir())
                with patch.object(env,'read_only_acl_report',side_effect=report):
                    if state=='correct':env.verify_installed(CONTROLLER)
                    else:
                        with self.assertRaises((OSError,SIDLabError)):env.verify_installed(CONTROLLER)


@unittest.skipUnless(os.name=='nt','Read-only Win32 checks require Windows')
class NativeReadOnlyTests(unittest.TestCase):
    def test_identity_checks_reject_admin_and_disabled_bypass_privileges(self):
        for failure in ('wrong_sid','deny_only_admin','disabled_backup','none'):
            with self.subTest(failure=failure),env._WindowsAccess() as access:
                c=access.c;w=access.w
                class Sid(c.Structure):_fields_=[('sid',c.c_void_p),('attributes',w.DWORD)]
                class Groups(c.Structure):_fields_=[('count',w.DWORD),('items',Sid*1)]
                class Luid(c.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
                class Privilege(c.Structure):_fields_=[('luid',Luid),('attributes',w.DWORD)]
                class Privileges(c.Structure):_fields_=[('count',w.DWORD),('items',Privilege*1)]
                user=c.create_string_buffer(c.sizeof(Sid));Sid.from_buffer(user).sid=1
                groups=c.create_string_buffer(c.sizeof(Groups));g=Groups.from_buffer(groups)
                g.count=1;g.items[0].sid=2;g.items[0].attributes=0x10  # SE_GROUP_USE_FOR_DENY_ONLY
                privileges=c.create_string_buffer(c.sizeof(Privileges));p=Privileges.from_buffer(privileges)
                p.count=int(failure=='disabled_backup');p.items[0].luid.low=42;p.items[0].attributes=0
                def sid_text(sid):
                    if sid==1:return CONTROLLER if failure=='wrong_sid' else env.SID
                    return 'S-1-5-32-544' if failure=='deny_only_admin' else 'S-1-5-32-545'
                def privilege(system,name,pointer):
                    c.cast(pointer,c.POINTER(Luid)).contents.low=42 if name=='SeBackupPrivilege' else 99
                    return True
                buffers={1:user,2:groups,3:privileges}
                with patch.object(access,'_token_buffer',side_effect=lambda token,kind:buffers[kind]),patch.object(access,'_sid_text',side_effect=sid_text),patch.object(access,'privilege',side_effect=privilege):
                    if failure=='none':access._verify_identity(None)
                    else:
                        with self.assertRaises(SIDLabError):access._verify_identity(None)

    def test_real_controller_descriptor_read_no_worker_logon(self):
        with env._WindowsAccess() as access:
            with access.inspect(Path(__file__).resolve()) as info:
                self.assertFalse(info.is_directory)
                self.assertGreater(len(info.descriptor),0)
                self.assertTrue(info.report['owner'].startswith('S-'))
                self.assertTrue(all(type(ace['flags']) is int for ace in info.report['aces']))
            with self.assertRaisesRegex(SIDLabError,'audit_logon_required'):access.rights(info)

    def test_real_controller_token_and_memory_only_descriptors(self):
        # Read the CURRENT controller token. No LogonUser, impersonation, privilege
        # change or filesystem security write. This is NOT a worker-account test.
        with env._WindowsAccess() as access:
            c=access.c;w=access.w;primary=c.c_void_p();token=c.c_void_p()
            current=access.kernel.GetCurrentProcess;current.restype=w.HANDLE;current.argtypes=[]
            open_token=access.adv.OpenProcessToken
            open_token.restype=w.BOOL;open_token.argtypes=[w.HANDLE,w.DWORD,c.POINTER(c.c_void_p)]
            self.assertTrue(open_token(current(),0xa,c.byref(primary)))
            access.handles.append(primary)
            self.assertTrue(access.duplicate(primary,2,c.byref(token)))
            access.handles.append(token);access.token=token
            user=access._token_buffer(primary,1)
            actual_sid=access._sid_text(c.c_void_p.from_buffer(user).value)
            # The controller's token must be rejected as the configured worker.
            if actual_sid!=env.SID:
                with self.assertRaisesRegex(SIDLabError,'root_identity_not_verified'):access._verify_identity(primary)
            convert=access.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
            convert.restype=w.BOOL;convert.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p]
            def snapshot(sddl):
                descriptor=c.c_void_p()
                self.assertTrue(convert(sddl,1,c.byref(descriptor),None))
                try:return env._ObjectSecurity({},c.string_at(descriptor,access.sd_length(descriptor)),False)
                finally:self.assertFalse(access.free(descriptor))
            unrelated='S-1-5-21-111-222-333-444'
            write_only=snapshot('O:'+unrelated+'G:SYD:P(A;;0x2;;;'+actual_sid+')')
            self.assertEqual(access.rights(write_only),2)
            self.assertEqual(access.rights(write_only),2)  # Cached on descriptor bytes.
            denied=snapshot('O:'+unrelated+'G:SYD:P(D;;FA;;;'+actual_sid+')')
            self.assertEqual(access.rights(denied),0)
            # OWNER RIGHTS suppresses implicit WRITE_DAC for the owner.
            owner_denied=snapshot('O:'+actual_sid+'G:SYD:P(D;;0xc0000;;;OW)(A;;0x2;;;'+actual_sid+')')
            granted=access.rights(owner_denied)
            self.assertEqual(granted&0xc0000,0);self.assertEqual(granted&2,2)
            # A creator-supplied protected DACL can grant execute despite parent
            # inheritance. Never infer future no-execute from a parent's DACL.
            creator_execute=snapshot('O:'+actual_sid+'G:SYD:P(A;;0x20;;;'+actual_sid+')')
            self.assertEqual(access.rights(creator_execute)&env.EXECUTE,env.EXECUTE)
        self.assertFalse(access.cache);self.assertFalse(hasattr(access,'token'))

    def test_native_access_check_failure_or_unknown_denial_is_not_cached(self):
        with env._WindowsAccess() as access:
            c=access.c;access.token=c.c_void_p(123)
            info=env._ObjectSecurity({},b'synthetic',False)
            with patch.object(access,'access_check',return_value=False),self.assertRaisesRegex(SIDLabError,'audit_access_check_failed'):access.rights(info)
            self.assertFalse(access.cache)
            # BOOL success + FALSE AccessStatus with a sharing error is not a
            # verified denial; only ERROR_ACCESS_DENIED qualifies.
            def sharing_error(*unused):c.set_last_error(32);return True
            with patch.object(access,'access_check',side_effect=sharing_error),self.assertRaisesRegex(SIDLabError,'audit_access_status_invalid'):access.rights(info)
            self.assertFalse(access.cache)

    def test_reparse_and_changed_final_path_fail_before_descriptor_read(self):
        path=Path(__file__).resolve()
        for failure in ('reparse','changed_path','close_error'):
            with self.subTest(failure=failure),env._WindowsAccess() as access:
                def file_info(handle,kind,buffer,size):buffer[0]=0x400;return True
                def final_path(handle,buffer,size,flags):buffer.value='\\\\?\\C:\\synthetic\\elsewhere';return len(buffer.value)
                with patch.object(access,'security') as security:
                    if failure=='reparse':
                        with patch.object(access,'file_info',side_effect=file_info),self.assertRaisesRegex(SIDLabError,'environment_reparse_forbidden'):
                            with access.inspect(path):self.fail('reparse accepted')
                    elif failure=='changed_path':
                        with patch.object(access,'final_path',side_effect=final_path),self.assertRaisesRegex(SIDLabError,'audit_object_identity_failed'):
                            with access.inspect(path):self.fail('changed identity accepted')
                    else:
                        # Close the REAL read-only handle, then simulate a close
                        # error. Never leak a handle to manufacture this negative.
                        real_close=access.close
                        def close_error(handle):self.assertTrue(real_close(handle));return False
                        with patch.object(access,'close',side_effect=close_error),patch.object(access,'final_path',side_effect=final_path),self.assertRaisesRegex(SIDLabError,'audit_handle_close_failed'):
                            with access.inspect(path):self.fail('changed identity accepted')
                    security.assert_not_called()


class InstallerReviewTests(unittest.TestCase):
    def test_parse_and_isolated_acl_validation_no_installer_execution(self):
        if os.name!='nt' or not shutil.which('powershell.exe'):self.skipTest('Windows PowerShell required')
        installer=Path(__file__).resolve().parents[1]/'tools'/'experimental'/'Install-BrowserRunEnvironment-REVIEW.ps1'
        # Parse only; import TWO selected helpers, never dot-source the installer.
        script=r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:BROWSER_LAB_REVIEW_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'Installer syntax invalid'}
$functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Test-ExactAcl','New-ProtectedDirectory')},$true)
if ($functions.Count -ne 2) {throw 'Missing reviewed helpers'}
foreach ($fn in $functions) {. ([scriptblock]::Create($fn.Extent.Text))}
# Compile, but NEVER invoke, the actual native creation type to verify its syntax.
$definitions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type'},$true)
if ($definitions.Count -ne 1) {throw 'Unexpected native definition count'}
$nativeSource=$definitions[0].CommandElements[2].Value.Replace('BrowserLabReviewedCreate','BrowserLabNativeSignatureReview')
Add-Type -TypeDefinition $nativeSource
$worker='S-1-5-21-2213057978-1848420950-3946800094-1006'
$controller='S-1-5-21-2213057978-1848420950-3946800094-1001'
$expected=[ordered]@{'S-1-5-18'=0x1f01ff;'S-1-5-32-544'=0x1f01ff;$worker=0x1200a9;$controller=0x1200a9}
$good="O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;$worker)(A;OICI;FRFX;;;$controller)"
function Raw([string]$sddl) {New-Object Security.AccessControl.RawSecurityDescriptor($sddl)}
if (!(Test-ExactAcl (Raw $good) 'S-1-5-32-544' $expected $true)) {throw 'Valid descriptor rejected'}
$badOwner=$good.Replace('O:BA','O:SY')
$badProtection=$good.Replace('D:P','D:')
$badGrant=$good.Replace('FRFX','FA')
$badFlags=$good.Replace('OICI','OICIIO')
$badExtra=$good+"(A;OICI;FA;;;WD)"
foreach ($bad in @($badOwner,$badProtection,$badGrant,$badFlags,$badExtra)) {
 if (Test-ExactAcl (Raw $bad) 'S-1-5-32-544' $expected $true) {throw 'Unsafe descriptor accepted'}
}
if (Test-ExactAcl (Raw $good) 'S-1-5-32-544' $expected $false) {throw 'Directory flags accepted on file'}
$file=$good.Replace(';OICI;',';;')
if (!(Test-ExactAcl (Raw $file) 'S-1-5-32-544' $expected $false)) {throw 'File descriptor rejected'}
# Model ERROR_ALREADY_EXISTS: no directory, ACL or account operations occur.
Add-Type 'public static class BrowserLabReviewedCreate { public static void CreateNew(string p, string s) { throw new System.IO.IOException("already exists"); } }'
function Assert-NoReparse([string]$path) {}
$script:aclCalls=0
function Assert-ExactAcl($path,$expected,$directory) {$script:aclCalls++}
$caught=$false
try {New-ProtectedDirectory 'C:\synthetic\existing' '' $expected} catch {$caught=$true}
if (!$caught -or $script:aclCalls -ne 0) {throw 'Existing-directory race did not stop before ACL handling'}
# Verify the installer has no automatic removal, ACL repair or elevation calls.
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach ($command in $commands) {
 if ($command.GetCommandName() -in @('Remove-Item','Set-Acl','Start-Process','takeown','icacls')) {throw 'Forbidden recovery mutation'}
}
'isolated_review_helpers_verified'
'''
        child_env=dict(os.environ,BROWSER_LAB_REVIEW_SCRIPT=str(installer))
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=30,env=child_env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('isolated_review_helpers_verified',result.stdout)
        self.assertFalse(result.stderr.strip(),result.stderr)


if __name__=='__main__':unittest.main()
