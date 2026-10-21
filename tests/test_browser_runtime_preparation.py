from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from jarvis.experimental import browser_runtime_preparation as runtime
from jarvis.experimental import browser_worker_task as task


class RuntimePreparationTests(unittest.TestCase):
    def fixture(self,root):
        source=Path(root)/'source';source.mkdir();(source/'locales').mkdir()
        for name in runtime.FILES+('145.0.7632.6.manifest',):(source/name).write_bytes(b'synthetic-runtime-fixture')
        return source

    def test_staging_hashes_preserve_manifest_and_no_profiles(self):
        with tempfile.TemporaryDirectory() as root:
            source=self.fixture(root);destination=Path(root)/'stage'
            records=runtime.stage_runtime(str(source),str(destination))
            self.assertTrue(runtime.validate_runtime(destination,records))
            self.assertFalse(runtime.validate_runtime(destination,(records[0],)))
            self.assertTrue(any(r.name.endswith('.manifest') for r in records))
            self.assertNotIn('Cookies',[r.name for r in records])
            (destination/'chrome.exe').write_bytes(b'altered')
            self.assertFalse(runtime.validate_runtime(destination,records))

    def test_unexpected_executable_and_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            source=self.fixture(root);destination=Path(root)/'stage';records=runtime.stage_runtime(source,destination)
            self.assertFalse(runtime.validate_runtime(destination,(replace(records[0],name='../chrome.exe'),)))
            (destination/'unexpected.exe').write_bytes(b'x')
            self.assertFalse(runtime.validate_runtime(destination,records))
            with self.assertRaises(ValueError):runtime.stage_runtime(source,destination)

    def test_privileged_spec_is_worker_readonly_and_separate_from_profile(self):
        plan=runtime.privileged_review_spec(())
        self.assertTrue(plan['require_parent_chain_protected'])
        self.assertIn('FRFX',plan['executable_sddl'])
        self.assertNotIn(';;;WD',plan['executable_sddl'])
        self.assertNotIn(';;;BU',plan['executable_sddl'])
        self.assertTrue(plan['profile_separate'])

    def test_acl_insufficient_writable_or_agent_owned_rejected(self):
        from jarvis.experimental.chromium_sid_lab import SID
        report=dict(protected=True,owner='S-1-5-32-544',aces=[dict(sid=sid,mask=mask,qualifier='AccessAllowed')
            for sid,mask in (('S-1-5-18',0x1f01ff),('S-1-5-32-544',0x1f01ff),(SID,0x1200a9))])
        self.assertTrue(runtime.validate_runtime_acl(report))
        report['aces'][2]['mask']=0x1f01ff
        self.assertFalse(runtime.validate_runtime_acl(report))
        report['aces'][2]['mask']=0x1200a9;report['owner']='S-1-5-21-1-2-3-1001'
        self.assertFalse(runtime.validate_runtime_acl(report))


class WorkerTaskPreparationTests(unittest.TestCase):
    def setUp(self):self.plan=task.WorkerTaskPlan('S-1-5-21-1-2-3-1001')

    def test_least_privilege_password_logon_no_triggers_no_secret(self):
        xml=self.plan.xml()
        self.assertIn('LeastPrivilege',xml);self.assertIn('IgnoreNew',xml);self.assertIn('PT60S',xml)
        self.assertIn('<LogonType>Password</LogonType>',xml)
        self.assertNotIn('<Password>',xml)
        self.assertTrue(task.validate_registered_task(self.plan,xml,self.plan.security_descriptor,worker_protected=True))

    def test_missing_tampered_or_writable_task_denied(self):
        for xml in ('',self.plan.xml().replace('LeastPrivilege','HighestAvailable'),self.plan.xml().replace('worker.exe','cmd.exe'),self.plan.xml().replace('IgnoreNew','Parallel')):
            self.assertFalse(task.validate_registered_task(self.plan,xml,self.plan.security_descriptor,worker_protected=True))
        self.assertFalse(task.validate_registered_task(self.plan,self.plan.xml(),'D:(A;;FA;;;WD)',worker_protected=True))
        self.assertFalse(task.validate_registered_task(self.plan,self.plan.xml(),self.plan.security_descriptor,worker_protected=False))

    def test_duplicate_start_wrong_identity_or_unauthenticated_ipc(self):
        for sid,in_job,ipc in (('S-1-5-21-1-2-3-1001',True,True),(task.SID,False,True),(task.SID,True,False)):
            life=task.WorkerLifecycle();handle=life.reserve_start()
            with self.assertRaises(RuntimeError):life.reserve_start()
            self.assertFalse(life.confirm_started(handle,sid=sid,pid=123,in_job=in_job,standard=True,ipc_authenticated=ipc))
            self.assertFalse(life.safe_to_unregister)

    def test_supervisor_disappearance_is_not_claimed_as_process_death(self):
        life=task.WorkerLifecycle();handle=life.reserve_start()
        self.assertTrue(life.confirm_started(handle,sid=task.SID,pid=123,in_job=True,standard=True,ipc_authenticated=True))
        life.supervisor_lost()
        with self.assertRaises(RuntimeError):task.uninstall_review_spec(self.plan,life)
        self.assertFalse(life.confirm_stopped(handle,job_empty=False,handles_closed=True,profile_removed=True))
        self.assertTrue(life.confirm_stopped(handle,job_empty=True,handles_closed=True,profile_removed=True))
        self.assertTrue(task.uninstall_review_spec(self.plan,life)['require_no_running_instances'])
        with self.assertRaises(RuntimeError):task.launch_scheduled_worker(self.plan)


if __name__=='__main__':unittest.main()
