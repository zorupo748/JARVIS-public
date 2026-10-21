"""Synthetic diagnosis regression tests. Chromium is NEVER executed here."""
from contextlib import contextmanager, redirect_stdout, ExitStack
from dataclasses import asdict
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from jarvis.experimental import chromium_diagnostic as diag

OPERATOR = 'S-1-5-21-2213057978-1848420950-3946800094-1001'
LOCAL_APPDATA = r'C:\Users\diego\AppData\Local'
PLAYWRIGHT_EXE = LOCAL_APPDATA + r'\ms-playwright\chromium-1208\chrome-win64\chrome.exe'
OBSERVED_PLAYWRIGHT_SHA256 = 'ff0c99fc5bb2301cad77930aa76e5354cf2a5fefb7efdcf3b3bc10ba0550c015'
WINDOWS_ENVIRONMENT = {
    'PROGRAMDATA': r'C:\WindowsEnvironmentTestSentinel\ProgramData',
    'ALLUSERSPROFILE': r'C:\WindowsEnvironmentTestSentinel\ProgramData',
    'PROGRAMFILES': r'C:\WindowsEnvironmentTestSentinel\Program Files',
    'PROGRAMFILES(X86)': r'C:\WindowsEnvironmentTestSentinel\Program Files (x86)',
    'PROGRAMW6432': r'C:\WindowsEnvironmentTestSentinel\Program Files',
    'COMMONPROGRAMFILES': r'C:\WindowsEnvironmentTestSentinel\Common Files',
    'COMMONPROGRAMFILES(X86)': r'C:\WindowsEnvironmentTestSentinel\Common Files (x86)',
    'COMMONPROGRAMW6432': r'C:\WindowsEnvironmentTestSentinel\Common Files',
    'PROCESSOR_ARCHITECTURE': 'AMD64', 'NUMBER_OF_PROCESSORS': '8',
}
SENSITIVE_ENVIRONMENT = {
    key:'DO_NOT_LEAK_ENVIRONMENT' for key in
    ('OPENAI_API_KEY','ANTHROPIC_API_KEY','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN',
     'DATABASE_URL','PASSWORD','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SSLKEYLOGFILE',
     'CHROME_LOG_FILE','CHROME_USER_DATA_DIR','NODE_OPTIONS','PYTHONPATH','CUSTOM_SECRET')
}
DOM = ('<!doctype html><html><body data-executed="yes" data-clicked="yes">'
       '<output id="result">DIAGNOSTIC_CLICK_OK</output></body></html>')
LOG_BYTES = (b'[1:2:ERROR:network.cc(1)] Network service crashed DO_NOT_LEAK\n'
             b'[1:2:ERROR:sandbox.cc(2)] Failed to initialize sandbox: access is denied\n'
             b'[1:2:ERROR:job.cc(3)] AssignProcessToJobObject failed: invalid handle\n'
             b'[1:2:ERROR:loader.cc(4)] Failed to load DO_NOT_LEAK.dll\n'
             b'[1:2:ERROR:ipc.cc(5)] IPC connection failed\n'
             b'[1:2:FATAL:init.cc(6)] Check failed: DO_NOT_LEAK\n'
             b'https://DO_NOT_LEAK.invalid/?token=DO_NOT_LEAK C:\\Users\\DO_NOT_LEAK\n')


class FakeClock:
    def __init__(self):self.now = 0
    def __call__(self):return self.now


class FakeBackend:
    def __init__(self, clock):
        self.clock = clock;self.ledger = diag.ProcessLedger();self.created = False
        self.identity = {'sid': OPERATOR, 'elevated': False}
        self.error = None;self.dom = DOM;self.exit_at = .05;self.code = 0;self.log = None
        self.inspection_time = 0;self.root_exited_calls = 0;self.sample_calls = 0
        self.resumed = False;self.started = False;self.finished = False
        self.unknown_child = False;self.finish_error = False
        self.cleanup = dict(job_empty=True, root_stopped=True, handles_closed=True,
                            inventory_reconciled=True, job_total_processes=1, diagnostics=[])
        self.job_diagnostics=diag.job_diagnostic_state('job_list')
    def operator_identity(self):return self.identity
    def start(self, chromium, session, expected_hash, sid, *, environment_mode='minimal',job_launch_mode='job_list',
              logging_mode='disabled'):
        self.logging_mode=logging_mode
        self.environment_mode=environment_mode
        self.job_launch_mode=job_launch_mode;self.job_diagnostics=diag.job_diagnostic_state(job_launch_mode)
        self.started = True
        if self.error:raise self.error
        audit=self.job_diagnostics;audit['worker_in_job']='no'
        stages=['worker_job_query']
        for role in (('guard','supervisor') if job_launch_mode!='job_list' else ('supervisor',)):
            audit[role+'_limits']=diag.expected_job_limits()
            stages.extend(role+'_'+stage for stage in ('create','limits_set','limits_query','ui_query','limits_verify'))
        stages.extend(('port_create','port_associate'))
        if job_launch_mode!='job_list':stages.append('guard_port_associate')
        stages.extend(('job_list_attribute','process_create'))
        if job_launch_mode!='job_list':stages.append('guard_membership')
        if job_launch_mode=='guarded_assign':stages.extend(('supervisor_absent_before_assign','supervisor_assign'))
        stages.append('root_verification')
        audit['stages']=[{'stage':stage,'ok':True,'code':0} for stage in stages]
        self.created = True;self.session = session;session.mkdir()
        (session / 'dom.txt').write_text(self.dom, encoding='utf-8')
        (session / 'stderr.txt').write_text('Network service crashed DO_NOT_LEAK')
        if logging_mode=='verbose':
            (session/'logs').mkdir()
            if self.log is not None:diag.internal_log_path(session).write_bytes(self.log)
        fact = self.ledger.observe(100);fact.identity = fact.membership = 'verified';fact.instance_verified=True
        if self.unknown_child:
            child = self.ledger.observe(200);child.token_error = 5;child.membership = 'verified'
    def resume(self):
        self.resumed = True
        self.job_diagnostics['stages'].append({'stage':'resume_thread','ok':True,'code':0})
    def root_exited(self):self.root_exited_calls += 1;return self.clock.now >= self.exit_at
    def sample(self, deadline):self.sample_calls += 1;self.clock.now += self.inspection_time
    def output_exceeded(self):return False
    def wait(self, milliseconds):self.clock.now += milliseconds / 1000
    def exit_code(self):return self.code
    def finish(self, timeout):
        self.finished = True
        if self.finish_error:raise diag.DiagnosticError('simulated_cleanup_failure')
        if self.job_launch_mode!='job_list':self.job_diagnostics['guard_empty']=self.cleanup['job_empty']
        for role in (('supervisor','guard') if self.job_launch_mode!='job_list' else ('supervisor',)):
            self.job_diagnostics['final_accounting'][role]={
                'active':int(not self.cleanup['job_empty']),'total':1,'terminated':0}
        return self.cleanup


class DiagnosticTests(unittest.TestCase):
    @contextmanager
    def fixture(self, *, environment_mode='minimal',job_launch_mode='job_list',logging_mode='disabled'):
        with tempfile.TemporaryDirectory() as root, patch.object(diag, 'WORKSPACE', Path(root)):
            bundle = diag.prepare_bundle(environment_mode=environment_mode,job_launch_mode=job_launch_mode,
                                         logging_mode=logging_mode);clock = FakeClock();backend = FakeBackend(clock)
            yield bundle, clock, backend

    def run_fake(self, bundle, clock, backend, **kwargs):
        return diag.run_diagnostic(bundle, approved_chromium_sha256='a' * 64,
                                   acknowledge_diagnostic_only=True,
                                   _backend_factory=lambda: backend, _monotonic=clock, **kwargs)

    def test_prepare_only_no_runtime_access_or_launch(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.object(subprocess,'run',side_effect=AssertionError('no launch')):
            bundle = diag.prepare_bundle()
            self.assertEqual(set(p.name for p in bundle.iterdir()), {'fixture.html','manifest.json'})
            self.assertEqual((bundle/'fixture.html').read_text(),diag.HTML)
            self.assertFalse(diag.read_bundle(bundle)['production_launch_allowed'])

    def test_logging_is_disabled_by_default_and_command_only_adds_three_fixed_arguments(self):
        with self.fixture() as (bundle,clock,backend):
            manifest=diag.read_bundle(bundle)
            self.assertEqual(manifest['logging_mode'],'disabled')
            self.assertEqual(manifest['max_internal_log_bytes'],1048576)
            session=bundle/'session with spaces'
            baseline=diag.command(diag.DEFAULT_CHROMIUM,session)
            verbose=diag.command(diag.DEFAULT_CHROMIUM,session,logging_mode='verbose')
            additions=['--enable-logging','--v=1','--log-file='+str(session/'logs'/'chrome_debug.log')]
            self.assertEqual(verbose[:-4]+verbose[-1:],baseline)
            self.assertEqual(verbose[-4:-1],additions)
            self.assertEqual(verbose[-1],diag.DATA_URL)
            self.assertFalse(any(arg.startswith(('--enable-logging','--v=','--log-file')) for arg in baseline))

    def test_verbose_manifest_is_explicit_new_and_refuses_context_changes_or_raw_settings(self):
        for failure in ('missing','invalid','boolean','path','limit','environment','job'):
            with self.subTest(failure=failure),self.fixture(logging_mode='verbose') as (bundle,clock,backend):
                manifest=diag.read_bundle(bundle)
                if failure=='missing':manifest.pop('logging_mode')
                elif failure=='invalid':manifest['logging_mode']='stderr'
                elif failure=='boolean':manifest['logging_mode']=True
                elif failure=='path':manifest['log_file']=r'C:\DO_NOT_LEAK\external.log'
                elif failure=='limit':manifest['max_internal_log_bytes']=9999999
                elif failure=='environment':manifest['environment_mode']='windows_standard'
                else:manifest['job_launch_mode']='guarded_assign'
                (bundle/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(diag.DiagnosticError):self.run_fake(bundle,clock,backend)
                self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())
        for environment,job in (('windows_standard','job_list'),('minimal','guarded_assign'),('minimal','guarded_job_list')):
            with self.subTest(environment=environment,job=job),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                with self.assertRaisesRegex(diag.DiagnosticError,'logging_requires_minimal_job_list'):
                    diag.prepare_bundle(environment_mode=environment,job_launch_mode=job,logging_mode='verbose')
                self.assertFalse(list(Path(root).iterdir()))

    def test_verbose_run_reports_only_bounded_metadata_and_fixed_labels_even_on_timeout(self):
        with self.fixture(logging_mode='verbose') as (bundle,clock,backend):
            backend.log=LOG_BYTES;backend.dom='';backend.exit_at=999;backend.inspection_time=31
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['wait_outcome'],'wall_timeout');self.assertEqual(report['dom_status'],'empty')
            self.assertTrue(report['cleanup_verified']);self.assertEqual(backend.logging_mode,'verbose')
            self.assertEqual(report['internal_log'],{'presence':'present','size_bytes':len(LOG_BYTES),
                             'size_capped':False,'categories':list(diag.LOG_ERROR_CATEGORIES)})
            self.assertEqual(json.loads((bundle/'active-lease.json').read_text())['logging_mode'],'verbose')
            for file in bundle.glob('*.json'):
                self.assertNotIn('DO_NOT_LEAK',file.read_text());self.assertNotIn('ERROR:network.cc',file.read_text())
            self.assertFalse(report['production_launch_allowed']);self.assertFalse(report['isolation_verified'])
            with self.assertRaisesRegex(diag.DiagnosticError,'previous_diagnostic_requires_review'):
                self.run_fake(bundle,clock,backend)

    def test_log_is_not_read_after_uncertain_cleanup_or_when_logging_is_disabled(self):
        for mode in diag.LOGGING_MODES:
            with self.subTest(mode=mode),self.fixture(logging_mode=mode) as (bundle,clock,backend):
                backend.log=LOG_BYTES
                if mode=='verbose':backend.cleanup['job_empty']=False
                with patch.object(diag,'_open_internal_log',side_effect=AssertionError('must not open log')):
                    report=self.run_fake(bundle,clock,backend)
                self.assertEqual(report['internal_log']['presence'],'disabled' if mode=='disabled' else 'not_inspected')
                self.assertIsNone(report['internal_log']['size_bytes'])
                self.assertEqual(report['internal_log']['categories'],[])

    def test_oversized_log_on_immediate_exit_is_capped_and_not_a_functional_success(self):
        with self.fixture(logging_mode='verbose') as (bundle,clock,backend):
            backend.log=b'x'*(diag.MAX_INTERNAL_LOG+1);backend.exit_at=0
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['wait_outcome'],'exited')
            self.assertTrue(report['internal_log']['size_capped'])
            self.assertEqual(report['internal_log']['size_bytes'],diag.MAX_INTERNAL_LOG)
            self.assertIn({'stage':'internal_log_limit','code':0},report['diagnostics'])
            self.assertEqual(report['status'],'inconclusive');self.assertTrue(report['cleanup_verified'])

    def test_live_log_limit_or_unreadability_stops_monitor_and_still_runs_cleanup(self):
        for stage in ('internal_log_limit','internal_log_unreadable'):
            with self.subTest(stage=stage),self.fixture(logging_mode='verbose') as (bundle,clock,backend):
                backend.exit_at=999;backend.log=LOG_BYTES
                backend.output_exceeded=Mock(side_effect=diag.DiagnosticError(stage))
                backend.wait=Mock(side_effect=AssertionError('no waiting after log error'))
                report=self.run_fake(bundle,clock,backend)
                self.assertTrue(backend.finished);self.assertTrue(report['cleanup_verified'])
                self.assertIn({'stage':stage,'code':0},report['diagnostics'])
                self.assertEqual(report['status'],'inconclusive')
                self.assertEqual(report['internal_log']['presence'],'present')

    def test_verbose_mode_preserves_operator_hash_and_opt_in_gates(self):
        for failure in ('restricted','elevated','hash','opt_in'):
            with self.subTest(failure=failure),self.fixture(logging_mode='verbose') as (bundle,clock,backend):
                if failure=='restricted':backend.identity={'sid':diag.RESTRICTED_SID,'elevated':False}
                elif failure=='elevated':backend.identity={'sid':OPERATOR,'elevated':True}
                with self.assertRaises(diag.DiagnosticError):
                    diag.run_diagnostic(bundle,approved_chromium_sha256='' if failure=='hash' else 'a'*64,
                                        acknowledge_diagnostic_only=failure!='opt_in',
                                        _backend_factory=lambda:backend,_monotonic=clock)
                self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())

    def test_log_report_validation_refuses_raw_fields_values_unbounded_sizes_and_forged_modes(self):
        with self.fixture(logging_mode='verbose') as (bundle,clock,backend):
            backend.log=LOG_BYTES;reference=self.run_fake(bundle,clock,backend)
        for failure in ('raw','category','size','bool_size','duplicate','capped','mode','context','cleanup'):
            with self.subTest(failure=failure):
                report=json.loads(json.dumps(reference));log=report['internal_log']
                if failure=='raw':log['contents']='DO_NOT_LEAK'
                elif failure=='category':log['categories']=['DO_NOT_LEAK']
                elif failure=='size':log['size_bytes']=diag.MAX_INTERNAL_LOG+1
                elif failure=='bool_size':log['size_bytes']=True
                elif failure=='duplicate':log['categories']=[diag.LOG_ERROR_CATEGORIES[0]]*2
                elif failure=='capped':log['size_capped']=True
                elif failure=='mode':report['logging_mode']='disabled'
                elif failure=='context':report['environment_mode']='windows_standard'
                else:
                    report['job_empty']=False;report['cleanup_verified']=False;report['status']='inconclusive'
                with self.assertRaisesRegex(diag.DiagnosticError,'worker_report_invalid'):diag.validate_report(report)

    def test_minimal_environment_preserves_original_eight_entries_without_reading_parent(self):
        class NoParentReads:
            def get(self,key):raise AssertionError('minimal must not read parent environment')
        expected={'SystemRoot':r'C:\Windows','WINDIR':r'C:\Windows','PATH':r'C:\Windows\System32',
                  'TEMP':r'E:\diagnostic\session\Temp','TMP':r'E:\diagnostic\session\Temp',
                  'USERPROFILE':r'E:\diagnostic\session\profile','APPDATA':r'E:\diagnostic\session\AppData',
                  'LOCALAPPDATA':r'E:\diagnostic\session\LocalAppData'}
        self.assertEqual(diag.diagnostic_environment('minimal',r'C:\Windows',r'E:\diagnostic\session',source=NoParentReads()),expected)

    def test_windows_standard_reads_only_allowlist_and_keeps_private_paths_and_path(self):
        reads=[]
        source=dict(WINDOWS_ENVIRONMENT,**SENSITIVE_ENVIRONMENT,
                    PATH='DO_NOT_LEAK_PARENT_PATH',TEMP='DO_NOT_LEAK_PARENT_TEMP',
                    USERPROFILE='DO_NOT_LEAK_PARENT_PROFILE',APPDATA='DO_NOT_LEAK_PARENT_APPDATA',
                    LOCALAPPDATA='DO_NOT_LEAK_PARENT_LOCALAPPDATA',COMSPEC='DO_NOT_LEAK_PARENT_COMSPEC')
        class ExplicitReadsOnly:
            def get(self,key):reads.append(key);return source.get(key)
            def __iter__(self):raise AssertionError('must not copy parent block')
            def items(self):raise AssertionError('must not enumerate parent block')
        baseline=diag.diagnostic_environment('minimal',r'C:\Windows',r'E:\diagnostic\session')
        expanded=diag.diagnostic_environment('windows_standard',r'C:\Windows',r'E:\diagnostic\session',source=ExplicitReadsOnly())
        allowed=set(diag.STANDARD_WINDOWS_PATH_VARIABLES+diag.STANDARD_WINDOWS_VALUE_VARIABLES)
        self.assertEqual(set(reads),allowed)
        self.assertEqual({key:expanded[key] for key in baseline},baseline)
        self.assertEqual(set(expanded),set(baseline)|allowed|{'COMSPEC','SYSTEMDRIVE','OS','HOMEDRIVE','HOMEPATH','PATHEXT'})
        self.assertEqual(expanded['COMSPEC'],r'C:\Windows\System32\cmd.exe')
        self.assertEqual(expanded['SYSTEMDRIVE'],'C:');self.assertEqual(expanded['HOMEDRIVE'],'E:')
        self.assertEqual(expanded['HOMEPATH'],r'\diagnostic\session\profile')
        self.assertEqual(source['PATH'],'DO_NOT_LEAK_PARENT_PATH')
        self.assertNotIn('DO_NOT_LEAK',json.dumps(expanded))

    def test_invalid_windows_standard_values_fail_without_disclosing_value(self):
        for key,value in (('PROGRAMDATA','https://DO_NOT_LEAK'),('PROGRAMDATA','C:\\DO_NOT_LEAK\0'),
                          ('PROGRAMDATA',r'\\server\DO_NOT_LEAK'),('PROGRAMDATA',r'C:\DO_NOT_LEAK\..\data'),
                          ('PROGRAMDATA',r'C:\DO_NOT_LEAK:stream'),('PROGRAMDATA',r'C:\DO_NOT_LEAK"bad'),
                          ('PROCESSOR_ARCHITECTURE','DO_NOT_LEAK'),('NUMBER_OF_PROCESSORS','DO_NOT_LEAK')):
            with self.subTest(key=key),self.assertRaises(diag.DiagnosticError) as caught:
                diag.diagnostic_environment('windows_standard',r'C:\Windows',r'E:\diagnostic\session',source={key:value})
            self.assertEqual(str(caught.exception),'windows_environment_value_invalid')
            self.assertNotIn('DO_NOT_LEAK',str(caught.exception))

    def test_unknown_environment_modes_and_unlabelled_old_bundles_fail_closed(self):
        for mode in ('inherit','full','',None,True):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                with self.assertRaises(diag.DiagnosticError):diag.prepare_bundle(environment_mode=mode)
                self.assertFalse(list(Path(root).iterdir()))
        for mode in (None,'inherit',{'API_KEY':'DO_NOT_LEAK'}):
            with self.subTest(manifest_mode=mode),self.fixture() as (bundle,clock,backend):
                manifest=diag.read_bundle(bundle)
                if mode is None:manifest.pop('environment_mode')
                else:manifest['environment_mode']=mode
                (bundle/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(diag.DiagnosticError):self.run_fake(bundle,clock,backend)
                self.assertFalse(backend.started)

    def test_comparison_uses_independent_bundles_and_labels_only_mode(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.dict(os.environ,dict(WINDOWS_ENVIRONMENT,**SENSITIVE_ENVIRONMENT)):
            first=diag.prepare_bundle(environment_mode='minimal')
            second=diag.prepare_bundle(environment_mode='windows_standard')
            self.assertNotEqual(first,second)
            minimal=diag.read_bundle(first);expanded=diag.read_bundle(second)
            self.assertEqual({key:value for key,value in minimal.items() if key!='environment_mode'},
                             {key:value for key,value in expanded.items() if key!='environment_mode'})
            self.assertEqual((first/'fixture.html').read_bytes(),(second/'fixture.html').read_bytes())
            for bundle,mode in ((first,'minimal'),(second,'windows_standard')):
                clock=FakeClock();backend=FakeBackend(clock)
                report=self.run_fake(bundle,clock,backend)
                self.assertEqual(backend.environment_mode,mode);self.assertEqual(report['environment_mode'],mode)
                self.assertEqual(report['status'],'synthetic_dom_observed')
                self.assertFalse(report['production_launch_allowed']);self.assertFalse(report['isolation_verified'])
                self.assertEqual(report['repository_audit'],{'status':'not_performed','complete':False})
                lease=json.loads((bundle/'active-lease.json').read_text());self.assertEqual(lease['environment_mode'],mode)
                recorded=''.join(path.read_text() for path in bundle.glob('*.json'))
                self.assertNotIn('DO_NOT_LEAK_ENVIRONMENT',recorded)
                self.assertNotIn('WindowsEnvironmentTestSentinel',recorded)
                self.assertNotIn('environment_values',recorded)
                with self.assertRaises(diag.DiagnosticError):self.run_fake(bundle,clock,backend)

    def test_both_environment_modes_keep_identity_navigation_and_time_limits(self):
        self.assertEqual((diag.CAPTURE_MS,diag.VIRTUAL_MS,diag.WALL_MS,diag.CLEANUP_MS,
                          diag.MAX_DOM,diag.MAX_STDERR,diag.MAX_PROCESSES),
                         (5000,1000,30000,6000,65536,262144,128))
        for mode in diag.ENVIRONMENT_MODES:
            for identity in ({'sid':diag.RESTRICTED_SID,'elevated':False},{'sid':OPERATOR,'elevated':True}):
                with self.subTest(mode=mode,identity=identity),self.fixture(environment_mode=mode) as (bundle,clock,backend):
                    args=diag.command(diag.DEFAULT_CHROMIUM,bundle/'session')
                    self.assertEqual(args[-1],diag.DATA_URL)
                    self.assertFalse(any(arg.startswith(('http:','https:','--no-sandbox','--remote-debugging')) for arg in args))
                    backend.identity=identity
                    with self.assertRaises(diag.DiagnosticError):self.run_fake(bundle,clock,backend)
                    self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())

    def test_both_environment_modes_require_opt_in_and_explicit_hash_approval(self):
        for mode in diag.ENVIRONMENT_MODES:
            for approved,acknowledged in (('a'*64,False),('',True),('not-approved',True)):
                with self.subTest(mode=mode,approved=approved,acknowledged=acknowledged),self.fixture(environment_mode=mode) as (bundle,clock,backend):
                    with self.assertRaises(diag.DiagnosticError):
                        diag.run_diagnostic(bundle,approved_chromium_sha256=approved,
                                            acknowledge_diagnostic_only=acknowledged,
                                            _backend_factory=lambda:backend,_monotonic=clock)
                    self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())

    def test_job_methods_use_fresh_bundles_with_same_fixture_environment_and_restrictions(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
            bundles=[diag.prepare_bundle(job_launch_mode=mode) for mode in diag.JOB_LAUNCH_MODES]
            self.assertEqual(len(set(bundles)),len(diag.JOB_LAUNCH_MODES))
            reference=None
            for bundle,mode in zip(bundles,diag.JOB_LAUNCH_MODES):
                with self.subTest(mode=mode):
                    manifest=diag.read_bundle(bundle)
                    comparable={key:value for key,value in manifest.items() if key!='job_launch_mode'}
                    if reference is None:reference=comparable
                    self.assertEqual(comparable,reference)
                    self.assertEqual((bundle/'fixture.html').read_bytes(),diag.HTML.encode('ascii'))
                    clock=FakeClock();backend=FakeBackend(clock)
                    report=self.run_fake(bundle,clock,backend)
                    self.assertEqual(report['job_launch_mode'],mode);self.assertEqual(backend.job_launch_mode,mode)
                    self.assertEqual(report['status'],'synthetic_dom_observed')
                    self.assertFalse(report['production_launch_allowed']);self.assertFalse(report['isolation_verified'])
                    self.assertEqual(report['repository_audit'],{'status':'not_performed','complete':False})
                    self.assertFalse(report['job_diagnostics']['events_complete'])
                    self.assertEqual(json.loads((bundle/'active-lease.json').read_text())['job_launch_mode'],mode)
                    self.assertNotIn('DO_NOT_LEAK',json.dumps(report))
                    with self.assertRaisesRegex(diag.DiagnosticError,'previous_diagnostic_requires_review'):
                        self.run_fake(bundle,clock,backend)

    def test_invalid_or_missing_job_method_denies_before_launch(self):
        for mode in ('uncontained','suspended_assign','breakaway','',None,True):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                with self.assertRaisesRegex(diag.DiagnosticError,'invalid_job_launch_mode'):
                    diag.prepare_bundle(job_launch_mode=mode)
                self.assertFalse(list(Path(root).iterdir()))
            with self.subTest(manifest_mode=mode),self.fixture() as (bundle,clock,backend):
                manifest=diag.read_bundle(bundle)
                if mode is None:manifest.pop('job_launch_mode')
                else:manifest['job_launch_mode']=mode
                (bundle/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(diag.DiagnosticError,'invalid_job_launch_mode'):
                    self.run_fake(bundle,clock,backend)
                self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())

    def test_all_job_methods_keep_identity_hash_approval_and_fixed_navigation(self):
        for mode in diag.JOB_LAUNCH_MODES:
            for failure in ('restricted','elevated','unapproved','not_acknowledged'):
                with self.subTest(mode=mode,failure=failure),self.fixture(job_launch_mode=mode) as (bundle,clock,backend):
                    if failure=='restricted':backend.identity={'sid':diag.RESTRICTED_SID,'elevated':False}
                    if failure=='elevated':backend.identity={'sid':OPERATOR,'elevated':True}
                    with self.assertRaises(diag.DiagnosticError):
                        diag.run_diagnostic(bundle,approved_chromium_sha256='' if failure=='unapproved' else 'a'*64,
                                            acknowledge_diagnostic_only=failure!='not_acknowledged',
                                            _backend_factory=lambda:backend,_monotonic=clock)
                    self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())
                    args=diag.command(diag.DEFAULT_CHROMIUM,bundle/'session')
                    self.assertEqual(args[-1],diag.DATA_URL)
                    self.assertFalse(any(a.startswith(('http:','https:','--no-sandbox','--remote-debugging','--disable-setuid-sandbox')) for a in args))

    def test_job_report_rejects_forged_limits_modes_unbounded_events_and_sensitive_fields(self):
        for mode in diag.JOB_LAUNCH_MODES:
            with self.fixture(job_launch_mode=mode) as (bundle,clock,backend):
                reference=self.run_fake(bundle,clock,backend)
            for failure in ('mode','breakaway','ui','active_cap','missing_phase','secret','counter','complete','guard'):
                with self.subTest(mode=mode,failure=failure):
                    report=json.loads(json.dumps(reference));audit=report['job_diagnostics']
                    if failure=='mode':audit['launch_mode']='uncontained'
                    elif failure=='breakaway':audit['supervisor_limits']['limit_flags']|=0x1000
                    elif failure=='ui':audit['supervisor_limits']['ui_restrictions']=1
                    elif failure=='active_cap':audit['supervisor_limits']['active_process_limit']=0
                    elif failure=='missing_phase':audit['stages']=[s for s in audit['stages'] if s['stage']!='root_verification']
                    elif failure=='secret':audit['environment']='DO_NOT_LEAK'
                    elif failure=='counter':audit['events']['new_process']=65537
                    elif failure=='complete':audit['events_complete']=True
                    elif mode=='job_list':audit['guard_limits']=diag.expected_job_limits()
                    else:audit['guard_empty']=False
                    with self.assertRaisesRegex(diag.DiagnosticError,'worker_report_invalid'):diag.validate_report(report)

    def test_ignored_job_fields_are_not_mistaken_for_active_limits(self):
        limits=diag.expected_job_limits();limits['scheduling_class']=5;limits['affinity']=255
        self.assertTrue(diag.job_limits_match(limits))
        limits['limit_flags']|=0x80
        self.assertFalse(diag.job_limits_match(limits))

    def test_timeout_reports_still_require_ordered_containment_before_resume(self):
        for mode in diag.JOB_LAUNCH_MODES:
            with self.fixture(job_launch_mode=mode) as (bundle,clock,backend):
                backend.exit_at=999;backend.inspection_time=31;backend.dom=''
                reference=self.run_fake(bundle,clock,backend)
                self.assertEqual(reference['wait_outcome'],'wall_timeout')
                self.assertTrue(reference['cleanup_verified'])
            for failure in ('missing_verification','resume_first','active_after_cleanup','missing_accounting'):
                with self.subTest(mode=mode,failure=failure):
                    report=json.loads(json.dumps(reference));audit=report['job_diagnostics']
                    if failure=='missing_verification':
                        audit['stages']=[s for s in audit['stages'] if s['stage']!='root_verification']
                    elif failure=='resume_first':audit['stages'].insert(0,audit['stages'].pop())
                    elif failure=='active_after_cleanup':audit['final_accounting']['supervisor']['active']=1
                    else:audit['final_accounting']['supervisor']=None
                    with self.assertRaisesRegex(diag.DiagnosticError,'worker_report_invalid'):
                        diag.validate_report(report)

    def test_no_public_url_or_sandbox_bypass_or_debug_endpoint(self):
        with self.fixture() as (bundle, clock, backend):
            arguments = diag.command(diag.DEFAULT_CHROMIUM, bundle/'session')
            self.assertEqual(arguments[-1],diag.DATA_URL)
            self.assertEqual(sum(a.startswith('data:') for a in arguments),1)
            self.assertFalse(any(a.startswith(('http:','https:','file:')) for a in arguments))
            self.assertFalse(any(a.startswith(('--no-sandbox','--disable-setuid-sandbox','--remote-debugging')) for a in arguments))
            self.assertIn('--timeout=5000',arguments);self.assertIn('--virtual-time-budget=1000',arguments)
            self.assertIn("connect-src 'none'",diag.HTML)

    def test_invalid_paths_and_urls_deny(self):
        for path in ('https://example.com',r'E:\JARVIS-opencode\chrome.exe',r'E:\JARVIS\chrome.exe',
                     r'\\server\share\chrome.exe',r'C:\Program Files\x\..\chrome.exe',
                     'C:\\Program Files\\x\\chrome.exe\n',r'C:\Program Files\x\cmd.exe'):
            with self.subTest(path=path),self.assertRaises(diag.DiagnosticError):diag.chromium_path(path)
        for name in ('existing','../other','chromium-diagnostic-review-'+('a'*31)):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),self.assertRaises(diag.DiagnosticError):
                diag.bundle_path(Path(root)/name)

    def test_exact_playwright_location_is_derived_from_operator_localappdata(self):
        for root in (LOCAL_APPDATA, r'D:\Profiles\other-operator\AppData\Local'):
            with self.subTest(root=root),patch.dict(os.environ,{'LOCALAPPDATA':root}):
                expected=root+r'\ms-playwright\chromium-1208\chrome-win64\chrome.exe'
                self.assertEqual(diag.chromium_path(expected),expected)
                self.assertEqual(diag.chromium_path(diag.DEFAULT_CHROMIUM),diag.DEFAULT_CHROMIUM)
                if root!=LOCAL_APPDATA:
                    with self.assertRaises(diag.DiagnosticError):diag.chromium_path(PLAYWRIGHT_EXE)

    def test_playwright_does_not_allow_other_profile_paths_or_path_aliases(self):
        rejected = (
            PLAYWRIGHT_EXE.replace('chromium-1208','chromium-1209'),
            PLAYWRIGHT_EXE.replace('chromium-1208','chromium-1208-copy'),
            PLAYWRIGHT_EXE.replace('chrome-win64','chrome-win'),
            PLAYWRIGHT_EXE.replace('chrome-win64','chrome-win32'),
            PLAYWRIGHT_EXE.replace('ms-playwright','ms-playwright-copy'),
            PLAYWRIGHT_EXE.replace('diego','other-user'),
            PLAYWRIGHT_EXE.replace('chrome.exe','headless_shell.exe'),
            PLAYWRIGHT_EXE.replace('chrome.exe','chrome.exe:payload'),
            PLAYWRIGHT_EXE.replace('chrome-win64',r'chrome-win64\..\chrome-win64'),
            PLAYWRIGHT_EXE.replace('chrome-win64',r'chrome-win64\.'),
            PLAYWRIGHT_EXE.replace('chromium-1208','chromium-1208.'),
            PLAYWRIGHT_EXE.replace('chromium-1208','chromium-1208 '),
            PLAYWRIGHT_EXE.replace('ms-playwright','ms-playwright:stream'),
            PLAYWRIGHT_EXE+'\\', PLAYWRIGHT_EXE+'\x00', PLAYWRIGHT_EXE+'\r',
            PLAYWRIGHT_EXE+'\n', PLAYWRIGHT_EXE+'\t', '"'+PLAYWRIGHT_EXE+'"',
            r'\\?'+'\\'+PLAYWRIGHT_EXE, '%LOCALAPPDATA%'+PLAYWRIGHT_EXE[len(LOCAL_APPDATA):],
            LOCAL_APPDATA+r'\chrome.exe', LOCAL_APPDATA+r'\Downloads\chrome.exe',
            LOCAL_APPDATA+r'\ms-playwright\chrome.exe',
        )
        with patch.dict(os.environ,{'LOCALAPPDATA':LOCAL_APPDATA}):
            for value in rejected:
                with self.subTest(path=value),self.assertRaisesRegex(diag.DiagnosticError,'invalid_chromium_path'):
                    diag.chromium_path(value)

    def test_playwright_fails_closed_with_missing_or_invalid_localappdata(self):
        for local in (None,'',r'AppData\Local',r'C:AppData\Local',r'\\server\profile\Local',
                      r'\\?\C:\Users\diego\AppData\Local',LOCAL_APPDATA+'\\',
                      LOCAL_APPDATA+r'\..\Local',LOCAL_APPDATA+':stream',LOCAL_APPDATA+'\n'):
            with self.subTest(local=local),patch.dict(os.environ):
                if local is None:os.environ.pop('LOCALAPPDATA',None)
                else:os.environ['LOCALAPPDATA']=local
                with self.assertRaises(diag.DiagnosticError):diag.chromium_path(PLAYWRIGHT_EXE)
                self.assertEqual(diag.chromium_path(diag.DEFAULT_CHROMIUM),diag.DEFAULT_CHROMIUM)

    def test_playwright_bundle_roundtrip_does_not_approve_observed_hash(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.dict(os.environ,{'LOCALAPPDATA':LOCAL_APPDATA}):
            bundle=diag.prepare_bundle(chromium=PLAYWRIGHT_EXE)
            manifest=diag.read_bundle(bundle)
            self.assertEqual(manifest['chromium'],PLAYWRIGHT_EXE)
            self.assertNotIn(OBSERVED_PLAYWRIGHT_SHA256,(bundle/'manifest.json').read_text())
            self.assertFalse(manifest['production_launch_allowed'])
            factory=Mock(side_effect=AssertionError('must not start without explicit hash'))
            with self.assertRaisesRegex(diag.DiagnosticError,'approved_runtime_hash_required'):
                diag.run_diagnostic(bundle,approved_chromium_sha256=None,
                                    acknowledge_diagnostic_only=True,_backend_factory=factory)
            factory.assert_not_called()
            with patch.dict(os.environ,{'LOCALAPPDATA':r'C:\Users\other\AppData\Local'}),self.assertRaises(diag.DiagnosticError):
                diag.read_bundle(bundle)

    def test_playwright_success_uses_explicit_runtime_hash_and_stays_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.dict(os.environ,{'LOCALAPPDATA':LOCAL_APPDATA}):
            bundle=diag.prepare_bundle(chromium=PLAYWRIGHT_EXE)
            clock=FakeClock();backend=FakeBackend(clock);backend.start=Mock(wraps=backend.start)
            report=diag.run_diagnostic(bundle,approved_chromium_sha256=OBSERVED_PLAYWRIGHT_SHA256,
                                       acknowledge_diagnostic_only=True,
                                       _backend_factory=lambda:backend,_monotonic=clock)
            backend.start.assert_called_once_with(PLAYWRIGHT_EXE,bundle/'session',OBSERVED_PLAYWRIGHT_SHA256,OPERATOR,environment_mode='minimal',job_launch_mode='job_list',logging_mode='disabled')
            self.assertEqual(report['status'],'synthetic_dom_observed')
            self.assertFalse(report['production_launch_allowed']);self.assertFalse(report['isolation_verified'])

    def test_success_branch_requires_empty_diagnostics_even_with_valid_dom_and_cleanup(self):
        for diagnostics,expected in (([],'synthetic_dom_observed'),
                                     ([{'stage':'job_events','code':5}],'inconclusive')):
            with self.subTest(diagnostics=diagnostics),self.fixture() as (bundle,clock,backend):
                backend.cleanup['diagnostics']=diagnostics
                # Execute run_diagnostic through report creation with a fake
                # backend. Every predicate before `not diagnostics` is true, so
                # reintroducing `notresult` raises NameError and fails this test.
                with patch('jarvis.experimental.chromium_diagnostic_win32.WindowsDiagnostic',side_effect=AssertionError('native backend forbidden')),patch.object(subprocess,'Popen',side_effect=AssertionError('process launch forbidden')):
                    report=self.run_fake(bundle,clock,backend)
                self.assertTrue(backend.started);self.assertTrue(backend.resumed);self.assertTrue(backend.finished)
                self.assertTrue(report['dom_markers_observed']);self.assertTrue(report['cleanup_verified'])
                self.assertEqual(report['exit_code'],0);self.assertEqual(report['wait_outcome'],'exited')
                self.assertEqual(report['diagnostics'],diagnostics);self.assertEqual(report['status'],expected)
                self.assertFalse(report['production_launch_allowed']);self.assertFalse(report['isolation_verified'])
                report_path=bundle/'report.json'
                self.assertTrue(report_path.is_file())
                saved=json.loads(report_path.read_text(encoding='ascii'))
                self.assertEqual(saved,report)
                self.assertEqual(saved['status'],expected)
                self.assertEqual(saved['diagnostics'],diagnostics)

    def test_manifest_corruption_and_arbitrary_html_deny(self):
        for failure in ('duplicate','production','budget','boolean_schema','url','extra','fixture'):
            with self.subTest(failure=failure),self.fixture() as (bundle, clock, backend):
                manifest = diag.read_bundle(bundle)
                if failure=='production':manifest['production_launch_allowed']=True
                elif failure=='budget':manifest['wall_ms']=999999
                elif failure=='boolean_schema':manifest['schema']=True
                elif failure=='url':manifest['chromium']='https://example.com'
                elif failure=='extra':manifest['html']='DO_NOT_LEAK'
                elif failure=='fixture':(bundle/'fixture.html').write_text('<script>fetch("https://example.com")</script>')
                text=json.dumps(manifest)
                if failure=='duplicate':text=text[:-1]+',"schema":1}'
                (bundle/'manifest.json').write_text(text)
                with self.assertRaises(diag.DiagnosticError):self.run_fake(bundle,clock,backend)
                self.assertFalse(backend.started)

    def test_restricted_elevated_or_unknown_operator_cannot_launch_or_reserve(self):
        for identity in ({'sid':diag.RESTRICTED_SID,'elevated':False},
                         {'sid':OPERATOR,'elevated':True},{'sid':OPERATOR,'elevated':0},
                         {'sid':'unknown','elevated':False},{}):
            with self.subTest(identity=identity),self.fixture() as (bundle,clock,backend):
                backend.identity=identity
                with self.assertRaisesRegex(diag.DiagnosticError,'standard_operator_identity_required'):self.run_fake(bundle,clock,backend)
                self.assertFalse(backend.started);self.assertFalse((bundle/'active-lease.json').exists())

    def test_explicit_optin_and_approved_hash_required(self):
        with self.fixture() as (bundle,clock,backend):
            with self.assertRaises(diag.DiagnosticError):diag.run_diagnostic(bundle,approved_chromium_sha256='a'*64)
            for value in ('','x'*64,'A'*64,None):
                with self.subTest(value=value),self.assertRaises(diag.DiagnosticError):
                    diag.run_diagnostic(bundle,approved_chromium_sha256=value,acknowledge_diagnostic_only=True)

    def test_dom_diagnostic_does_not_grant_production_or_claim_repository_security(self):
        from jarvis.experimental import browser_run_environment as production
        with self.fixture() as (bundle,clock,backend),patch.object(production,'effective_access_check',side_effect=AssertionError('production gate must not be bypassed')),patch.object(production,'_audit_tree',side_effect=diag.DiagnosticError('repository_audit_limit')):
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['status'],'synthetic_dom_observed')
            self.assertEqual(report['repository_audit'],{'status':'not_performed','complete':False})
            self.assertIs(report['isolation_verified'],False);self.assertIs(report['production_launch_allowed'],False)
            self.assertFalse(report['restricted_account_tested'])
            self.assertNotIn('DO_NOT_LEAK',json.dumps(report));self.assertNotIn(diag.HTML,json.dumps(report))
            self.assertEqual(report['stderr_categories'],['network_service_crash_reported'])
            self.assertTrue((bundle/'active-lease.json').exists());self.assertTrue((bundle/'session').exists())
            with self.assertRaisesRegex(diag.DiagnosticError,'previous_diagnostic_requires_review'):self.run_fake(bundle,clock,backend)

    def test_unknown_child_does_not_become_a_mismatch_or_hide_dom_observation(self):
        with self.fixture() as (bundle,clock,backend):
            backend.unknown_child=True
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['status'],'synthetic_dom_observed')
            self.assertFalse(report['inspection_complete'])
            self.assertEqual(report['processes'][1],dict(process_type='unknown',membership='unknown',
                exit_code=None,exit_observed_ms=None,exit_phase='unknown'))
            self.assertFalse(report['exit_observation_complete'])
            self.assertFalse(report['isolation_verified'])

    def test_partial_process_inventory_never_certified(self):
        with self.fixture() as (bundle,clock,backend):
            backend.cleanup['inventory_reconciled']=False
            report=self.run_fake(bundle,clock,backend)
            self.assertFalse(report['process_inventory_complete']);self.assertFalse(report['inspection_complete'])

    def test_report_rejects_forged_security_extra_text_and_false_completeness(self):
        with self.fixture() as (bundle,clock,backend):
            backend.unknown_child=True
            valid=self.run_fake(bundle,clock,backend)
            diag.validate_report(valid)
            for failure in ('production','isolation','repository','inspection','cleanup','raw','stderr','environment_mode','environment_values'):
                with self.subTest(failure=failure):
                    report=json.loads(json.dumps(valid))
                    if failure=='production':report['production_launch_allowed']=True
                    elif failure=='isolation':report['isolation_verified']=True
                    elif failure=='repository':report['repository_audit']['complete']=True
                    elif failure=='inspection':report['inspection_complete']=True
                    elif failure=='cleanup':report['root_stopped']=False
                    elif failure=='raw':report['raw_stderr']='DO_NOT_LEAK'
                    elif failure=='stderr':report['stderr_categories']=['DO_NOT_LEAK']
                    elif failure=='environment_mode':report['environment_mode']='inherit'
                    else:report['environment_values']={'PASSWORD':'DO_NOT_LEAK'}
                    with self.assertRaises(diag.DiagnosticError):diag.validate_report(report)

    def test_exit_checked_before_inspection_avoids_false_timeout(self):
        clock=FakeClock();backend=FakeBackend(clock);backend.exit_at=0;backend.inspection_time=60
        self.assertEqual(diag.monitor(backend,30,monotonic=clock),'exited')
        self.assertEqual(backend.sample_calls,0)

    def test_inspection_time_consumes_wall_budget_without_extra_wait(self):
        clock=FakeClock();backend=FakeBackend(clock);backend.exit_at=999;backend.inspection_time=31
        backend.wait=Mock(side_effect=AssertionError('wait beyond deadline'))
        self.assertEqual(diag.monitor(backend,30,monotonic=clock),'wall_timeout')
        self.assertEqual(clock.now,31)

    def test_expired_startup_budget_never_resumes_root(self):
        with self.fixture() as (bundle,clock,backend):
            real_start=backend.start
            def slow_start(*args,**kwargs):real_start(*args,**kwargs);clock.now=31
            backend.start=slow_start
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['wait_outcome'],'wall_timeout')
            self.assertFalse(backend.resumed);self.assertTrue(backend.finished)
            self.assertEqual(report['status'],'inconclusive')

    def test_wall_timeout_preserves_partial_dom_and_uncertain_cleanup(self):
        with self.fixture() as (bundle,clock,backend):
            backend.exit_at=999;backend.inspection_time=31;backend.cleanup['job_empty']=False
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(report['wait_outcome'],'wall_timeout')
            self.assertEqual(report['dom_status'],'markers_observed')
            self.assertEqual(report['status'],'inconclusive');self.assertFalse(report['job_empty'])
            self.assertTrue(backend.finished);self.assertTrue(report['lease_retained'])

    def test_start_or_inspection_error_still_attempts_owned_cleanup(self):
        for error in (diag.DiagnosticError('runtime_open',5),diag.DiagnosticError('root_verification'),OSError('DO_NOT_LEAK')):
            with self.subTest(error=type(error)),self.fixture() as (bundle,clock,backend):
                backend.error=error
                report=self.run_fake(bundle,clock,backend)
                self.assertEqual(report['status'],'inconclusive');self.assertFalse(backend.resumed)
                self.assertTrue(backend.finished);self.assertNotIn('DO_NOT_LEAK',json.dumps(report))

    def test_cleanup_error_or_nonzero_exit_never_functional_success(self):
        for failure in ('cleanup_exception','root_running','handle_open','nonzero_exit'):
            with self.subTest(failure=failure),self.fixture() as (bundle,clock,backend):
                if failure=='cleanup_exception':backend.finish_error=True
                elif failure=='root_running':backend.cleanup['root_stopped']=False
                elif failure=='handle_open':backend.cleanup['handles_closed']=False
                else:backend.code=1
                report=self.run_fake(bundle,clock,backend)
                self.assertEqual(report['status'],'inconclusive')
                self.assertTrue((bundle/'active-lease.json').exists())

    def test_dom_missing_empty_oversized_encoding_and_source_only_are_distinct(self):
        for data,status in ((None,'missing'),(b'','empty'),(b' ' ,'empty'),(b'x'*(diag.MAX_DOM+1),'oversized'),
                            (b'\xff','invalid_encoding'),(diag.HTML.encode(),'markers_missing'),(DOM.encode(),'markers_observed')):
            with self.subTest(status=status),tempfile.TemporaryDirectory() as root:
                path=Path(root)/'dom.txt'
                if data is not None:path.write_bytes(data)
                observed,markers=diag.capture_dom(path)
                self.assertEqual(observed,status);self.assertEqual(markers,status=='markers_observed')

    def test_process_ledger_pid_reuse_unknown_exits_and_limits(self):
        ledger=diag.ProcessLedger();first=ledger.observe(123)
        self.assertIs(ledger.observe(123),first)
        first.exited=True;second=ledger.observe(123)
        self.assertEqual((first.sequence,second.sequence),(0,1));self.assertFalse(ledger.complete)
        for fact in ledger.facts:fact.identity=fact.membership='verified';fact.instance_verified=True
        self.assertTrue(ledger.complete)
        with patch.object(diag,'MAX_PROCESSES',2),self.assertRaisesRegex(diag.DiagnosticError,'process_observation_limit'):ledger.observe(456)
        for pid in (0,True,-1,4294967296):
            with self.subTest(pid=pid),self.assertRaises(diag.DiagnosticError):ledger.observe(pid)

    def test_process_generations_use_creation_not_arrival_order_or_pid_only_exits(self):
        ledger=diag.ProcessLedger();first=ledger.observe(123,creation=10)
        first.exited=True
        self.assertIs(ledger.observe(123,creation=10),first)  # Delayed NEW packet.
        second=ledger.observe(123,creation=20)
        self.assertIsNot(second,first);self.assertFalse(second.exited)
        self.assertFalse(hasattr(ledger,'exit'))  # No PID-only attribution API.

    def test_technical_types_are_fixed_and_arbitrary_switch_values_never_escape(self):
        cases=[([], 'unknown'),(['chrome'], 'unknown'),
               (['chrome','--type=renderer'],'renderer'),
               (['chrome','--type=gpu-process'],'gpu-process'),
               (['chrome','--type=utility'],'utility'),
               (['chrome','--type=utility','--utility-sub-type=network.mojom.NetworkService'],'network-service'),
               (['chrome','--type=utility','--utility-sub-type=DO_NOT_LEAK'],'utility'),
               (['chrome','--type=crashpad-handler'],'crashpad-handler'),
               (['chrome','--type=DO_NOT_LEAK'],'unknown'),
               (['chrome','--type=browser'],'unknown'),
               (['chrome','--type=renderer','--type=renderer'],'unknown'),
               (['chrome','--type','renderer'],'unknown'),
               (['chrome','--','--type=renderer'],'unknown'),
               (['chrome','--secret=--type=renderer'],'unknown'),
               (['chrome','--type=utility','--utility-sub-type=network.mojom.NetworkService',
                 '--utility-sub-type=DO_NOT_LEAK'],'unknown')]
        for arguments,expected in cases:
            with self.subTest(expected=expected):self.assertEqual(diag.technical_process_type(arguments),expected)

    def test_reports_export_only_technical_observations_and_completeness_is_fail_closed(self):
        with self.fixture() as (bundle,clock,backend):
            fact=backend.ledger.observe(200,creation=987654321)
            fact.instance_verified=True;fact.identity=fact.membership='verified'
            fact.process_type='network-service';fact.exited=True
            fact.exit_code=0xc0000005;fact.exit_observed_ms=1;fact.exit_phase='before_cleanup'
            # Fake start will append a root; the partial exit inventory stays false.
            report=self.run_fake(bundle,clock,backend)
            self.assertEqual(set(report['processes'][0]),
                {'process_type','membership','exit_code','exit_observed_ms','exit_phase'})
            self.assertFalse(report['exit_observation_complete'])
            self.assertNotIn('987654321',json.dumps(report))
            for mutation in ('raw','pid','type','phase','time','code','boolean','membership','complete','schema'):
                invalid=json.loads(json.dumps(report));entry=invalid['processes'][0]
                if mutation=='raw':entry['command_line']='DO_NOT_LEAK'
                elif mutation=='pid':entry['pid']=200
                elif mutation=='type':entry['process_type']='DO_NOT_LEAK'
                elif mutation=='phase':entry['exit_phase']='spontaneous_proven'
                elif mutation=='time':entry['exit_observed_ms']=invalid['elapsed_ms']+1
                elif mutation=='code':entry['exit_code']=-1
                elif mutation=='boolean':entry['exit_code']=True
                elif mutation=='membership':entry['membership']='unknown'
                elif mutation=='complete':invalid['exit_observation_complete']=True
                else:invalid['schema']=1
                with self.subTest(mutation=mutation),self.assertRaises(diag.DiagnosticError):diag.validate_report(invalid)

    def test_unverified_process_metadata_is_redacted_and_old_bundle_is_not_upgraded(self):
        fact=diag.ProcessFact(123,0,identity='unknown',membership='verified',instance_verified=True,
            process_type='renderer',exited=True,exit_code=5,exit_observed_ms=1,exit_phase='before_cleanup')
        self.assertEqual(diag.process_observation(fact),dict(process_type='unknown',membership='unknown',
            exit_code=None,exit_observed_ms=None,exit_phase='unknown'))
        with self.fixture() as (bundle,clock,backend):
            path=bundle/'manifest.json';manifest=json.loads(path.read_text());manifest['schema']=1
            original=json.dumps(manifest);path.write_text(original)
            with self.assertRaisesRegex(diag.DiagnosticError,'manifest_mismatch'):diag.read_bundle(bundle)
            self.assertEqual(path.read_text(),original);self.assertFalse(backend.started)

    def test_exit_completeness_requires_known_type_code_and_observed_exit_for_every_instance(self):
        with self.fixture() as (bundle,clock,backend):
            finish=backend.finish
            def finished(timeout):
                cleanup=finish(timeout)
                for fact in backend.ledger.facts:
                    fact.process_type='browser';fact.exited=True;fact.exit_code=0
                    fact.exit_observed_ms=0;fact.exit_phase='before_cleanup'
                return cleanup
            with patch.object(backend,'finish',side_effect=finished):report=self.run_fake(bundle,clock,backend)
            self.assertTrue(report['exit_observation_complete'])
            for field,value in (('process_type','unknown'),('exit_code',None)):
                partial=json.loads(json.dumps(report));partial['processes'][0][field]=value
                partial['exit_observation_complete']=False
                diag.validate_report(partial)
                partial['exit_observation_complete']=True
                with self.assertRaises(diag.DiagnosticError):diag.validate_report(partial)


class InternalLogTests(unittest.TestCase):
    def test_missing_empty_invalid_utf8_exact_limit_and_oversize_are_bounded(self):
        for data in (None,b'',b'\xff\xfeDO_NOT_LEAK',b'x'*diag.MAX_INTERNAL_LOG,b'x'*(diag.MAX_INTERNAL_LOG+1)):
            with self.subTest(size=None if data is None else len(data)),tempfile.TemporaryDirectory() as root:
                session=Path(root);(session/'logs').mkdir()
                if data is not None:diag.internal_log_path(session).write_bytes(data)
                summary=diag.internal_log_summary(session,'verbose')
                self.assertEqual(summary['presence'],'missing' if data is None else 'present')
                self.assertEqual(summary['size_bytes'],min(len(data or b''),diag.MAX_INTERNAL_LOG))
                self.assertEqual(summary['size_capped'],data is not None and len(data)>diag.MAX_INTERNAL_LOG)
                self.assertEqual(summary['categories'],[])
                self.assertNotIn('DO_NOT_LEAK',json.dumps(summary))

    def test_read_and_metadata_are_independently_bounded(self):
        file=Mock();file.read.return_value=LOG_BYTES
        @contextmanager
        def opened(path):yield file,10**12
        with patch.object(diag,'_open_internal_log',side_effect=opened):
            summary=diag.internal_log_summary(Path.cwd(),'verbose')
        file.read.assert_called_once_with(diag.MAX_INTERNAL_LOG+1)
        self.assertEqual(summary['size_bytes'],diag.MAX_INTERNAL_LOG);self.assertTrue(summary['size_capped'])
        file.read.reset_mock()
        with patch.object(diag,'_open_internal_log',side_effect=opened):
            summary=diag.internal_log_summary(Path.cwd(),'verbose',read=False)
        file.read.assert_not_called();self.assertEqual(summary['categories'],[])

    def test_hard_links_directories_and_reparse_errors_never_expose_target_contents(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)/'session';(session/'logs').mkdir(parents=True)
            external=Path(root)/'DO_NOT_LEAK.txt';external.write_bytes(LOG_BYTES)
            log=diag.internal_log_path(session)
            os.link(external,log)
            self.assertEqual(diag.internal_log_summary(session,'verbose')['presence'],'unreadable')
            log.unlink();log.mkdir()
            self.assertEqual(diag.internal_log_summary(session,'verbose')['presence'],'unreadable')
            with patch.object(diag,'no_reparse',side_effect=diag.DiagnosticError('reparse_forbidden')),patch.object(os,'fdopen') as opened:
                summary=diag.internal_log_summary(session,'verbose')
            opened.assert_not_called();self.assertEqual(summary['categories'],[])
            self.assertNotIn('DO_NOT_LEAK',json.dumps(summary))

    def test_read_errors_do_not_forward_os_messages_or_partial_content(self):
        @contextmanager
        def denied(path):raise OSError('DO_NOT_LEAK');yield
        with patch.object(diag,'_open_internal_log',side_effect=denied):
            summary=diag.internal_log_summary(Path.cwd(),'verbose')
        self.assertEqual(summary,{'presence':'unreadable','size_bytes':None,'size_capped':False,'categories':[]})


class DiagnosticCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).resolve().parents[1]/'tools'/'experimental'/'run_chromium_diagnostic.py'
        spec=importlib.util.spec_from_file_location('chromium_diagnostic_cli_test',path)
        cls.cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.cli)

    def test_cli_prepare_never_invokes_worker(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.object(self.cli.subprocess,'run') as execute,redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.cli.main(['prepare']),0)
            execute.assert_not_called();self.assertFalse(json.loads(output.getvalue())['browser_launched'])

    def test_cli_prepares_one_verbose_bundle_without_opening_runtime_or_launching(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.object(self.cli.subprocess,'run',side_effect=AssertionError('no launch')),patch('jarvis.experimental.chromium_diagnostic_win32.WindowsDiagnostic',side_effect=AssertionError('no runtime access')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.cli.main(['prepare','--logging-mode','verbose']),0)
            result=json.loads(output.getvalue());bundle=Path(result['bundle'])
            self.assertEqual(result['logging_mode'],'verbose');self.assertFalse(result['browser_launched'])
            self.assertEqual(len(list(Path(root).iterdir())),1)
            self.assertEqual({p.name for p in bundle.iterdir()},{'manifest.json','fixture.html'})
            manifest=diag.read_bundle(bundle)
            self.assertEqual((manifest['environment_mode'],manifest['job_launch_mode']),('minimal','job_list'))

    def test_cli_logging_mode_cannot_be_changed_by_worker_or_run_override(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
            expected=diag.prepare_bundle(logging_mode='verbose');other=diag.prepare_bundle()
            clock=FakeClock();backend=FakeBackend(clock)
            report=diag.run_diagnostic(other,approved_chromium_sha256='a'*64,acknowledge_diagnostic_only=True,
                                       _backend_factory=lambda:backend,_monotonic=clock)
            with patch.object(self.cli.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(report))),redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.main(['run','--bundle',str(expected),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only']),2)
            self.assertEqual(json.loads(output.getvalue())['diagnostic_stage'],'worker_report_invalid')
        with redirect_stdout(io.StringIO()),patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit):
            self.cli.main(['run','--bundle','unused','--approved-chromium-sha256','a'*64,'--logging-mode','verbose'])

    def test_verbose_watchdog_never_reads_or_claims_presence_of_log(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
            bundle=diag.prepare_bundle(logging_mode='verbose')
            with patch.object(self.cli.subprocess,'run',side_effect=subprocess.TimeoutExpired('synthetic',46)),patch.object(diag,'_open_internal_log',side_effect=AssertionError('no log inspection')),redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only']),2)
            report=json.loads(output.getvalue());self.assertFalse(report['cleanup_verified'])
            self.assertEqual(report['internal_log']['presence'],'not_inspected')
            self.assertEqual(report['logging_mode'],'verbose')

    def test_inspect_log_is_read_only_sanitized_and_requires_verified_cleanup(self):
        for cleaned in (True,False):
            with self.subTest(cleaned=cleaned),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                bundle=diag.prepare_bundle(logging_mode='verbose');clock=FakeClock();backend=FakeBackend(clock)
                backend.log=LOG_BYTES;backend.cleanup['job_empty']=cleaned
                diag.run_diagnostic(bundle,approved_chromium_sha256='a'*64,acknowledge_diagnostic_only=True,
                                    _backend_factory=lambda:backend,_monotonic=clock)
                previous={str(p):p.read_bytes() for p in bundle.rglob('*') if p.is_file()}
                with patch.object(self.cli.subprocess,'run',side_effect=AssertionError('no launch')),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['inspect-log','--bundle',str(bundle)]),0 if cleaned else 2)
                result=json.loads(output.getvalue());self.assertFalse(result['production_launch_allowed'])
                self.assertEqual(result['internal_log']['presence'],'present' if cleaned else 'not_inspected')
                self.assertNotIn('DO_NOT_LEAK',output.getvalue())
                self.assertEqual(previous,{str(p):p.read_bytes() for p in bundle.rglob('*') if p.is_file()})

    def test_inspect_log_rejects_tampered_report_before_opening_log(self):
        for failure in ('raw','mode','duplicate'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                bundle=diag.prepare_bundle(logging_mode='verbose');clock=FakeClock();backend=FakeBackend(clock)
                report=diag.run_diagnostic(bundle,approved_chromium_sha256='a'*64,acknowledge_diagnostic_only=True,
                                           _backend_factory=lambda:backend,_monotonic=clock)
                if failure=='raw':report['internal_log']['raw']='DO_NOT_LEAK'
                if failure=='mode':
                    report['logging_mode']='disabled';report['internal_log']=diag.internal_log_summary(None,'disabled')
                text=json.dumps(report)
                if failure=='duplicate':text=text[:-1]+',"logging_mode":"verbose"}'
                (bundle/'report.json').write_text(text)
                with patch.object(self.cli.subprocess,'run',side_effect=AssertionError('no launch')),patch.object(diag,'_open_internal_log',side_effect=AssertionError('no read')),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['inspect-log','--bundle',str(bundle)]),2)
                self.assertNotIn('DO_NOT_LEAK',output.getvalue())
                self.assertEqual(json.loads(output.getvalue())['diagnostic_stage'],'worker_report_invalid')

    def test_cli_job_comparison_prepares_independent_labelled_bundles_without_launch(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.object(self.cli.subprocess,'run',side_effect=AssertionError('no launch')):
            bundles=[]
            for mode in diag.JOB_LAUNCH_MODES:
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['prepare','--job-launch-mode',mode]),0)
                result=json.loads(output.getvalue());bundles.append(result['bundle'])
                self.assertEqual(result['job_launch_mode'],mode)
                self.assertFalse(result['browser_launched'])
                self.assertEqual(diag.read_bundle(Path(result['bundle']))['job_launch_mode'],mode)
            self.assertEqual(len(set(bundles)),3)

    def test_watchdog_preserves_each_job_method_without_certifying_cleanup(self):
        for mode in diag.JOB_LAUNCH_MODES:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                bundle=diag.prepare_bundle(job_launch_mode=mode)
                error=subprocess.TimeoutExpired('synthetic',46,output=b'DO_NOT_LEAK')
                with patch.object(self.cli.subprocess,'run',side_effect=error),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only']),2)
                report=json.loads(output.getvalue())
                self.assertEqual(report['job_launch_mode'],mode)
                self.assertIsNone(report['job_diagnostics'])
                self.assertFalse(report['cleanup_verified']);self.assertFalse(report['job_empty'])
                self.assertEqual(json.loads((bundle/'active-lease.json').read_text())['job_launch_mode'],mode)
                self.assertNotIn('DO_NOT_LEAK',output.getvalue())

    def test_worker_cannot_change_job_method_or_override_it_at_run_time(self):
        for selected,returned in (('job_list','guarded_assign'),('guarded_assign','guarded_job_list')):
            with self.subTest(selected=selected),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                expected=diag.prepare_bundle(job_launch_mode=selected)
                other=diag.prepare_bundle(job_launch_mode=returned)
                clock=FakeClock();backend=FakeBackend(clock)
                report=diag.run_diagnostic(other,approved_chromium_sha256='a'*64,
                                           acknowledge_diagnostic_only=True,
                                           _backend_factory=lambda:backend,_monotonic=clock)
                with patch.object(self.cli.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(report))),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['run','--bundle',str(expected),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only']),2)
                self.assertEqual(json.loads(output.getvalue())['diagnostic_stage'],'worker_report_invalid')
        with redirect_stdout(io.StringIO()),patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit):
            self.cli.main(['run','--bundle','unused','--approved-chromium-sha256','a'*64,
                           '--acknowledge-diagnostic-only','--job-launch-mode','guarded_assign'])

    def test_cli_prepares_fresh_bundles_for_both_environment_modes_without_reading_values(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.dict(os.environ,SENSITIVE_ENVIRONMENT),patch.object(self.cli.subprocess,'run',side_effect=AssertionError('no launch')),patch.object(diag,'diagnostic_environment',side_effect=AssertionError('prepare must not read environment values')):
            bundles=[]
            for mode in diag.ENVIRONMENT_MODES:
                with self.subTest(mode=mode),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['prepare','--environment-mode',mode]),0)
                value=json.loads(output.getvalue());bundles.append(value['bundle'])
                self.assertEqual(value['environment_mode'],mode);self.assertFalse(value['browser_launched'])
                self.assertEqual(diag.read_bundle(Path(value['bundle']))['environment_mode'],mode)
                self.assertNotIn('DO_NOT_LEAK',output.getvalue())
            self.assertEqual(len(set(bundles)),2)

    def test_cli_refuses_inherited_environment_and_run_time_mode_overrides(self):
        for argv in (['prepare','--environment-mode','inherit'],
                     ['run','--bundle','unused','--approved-chromium-sha256','a'*64,
                      '--environment-mode','windows_standard']):
            with self.subTest(argv=argv),redirect_stdout(io.StringIO()),patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit) as error:
                self.cli.main(argv)
            self.assertEqual(error.exception.code,2)

    def test_cli_prepare_accepts_exact_playwright_without_starting_any_worker(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)),patch.dict(os.environ,{'LOCALAPPDATA':LOCAL_APPDATA}),patch.object(self.cli.subprocess,'run',side_effect=AssertionError('must not launch')),patch('jarvis.experimental.chromium_diagnostic_win32.WindowsDiagnostic',side_effect=AssertionError('must not inspect or launch')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.cli.main(['prepare','--chromium',PLAYWRIGHT_EXE]),0)
            report=json.loads(output.getvalue());self.assertEqual(report['mode'],'prepared_only')
            self.assertFalse(report['browser_launched']);self.assertFalse(report['production_launch_allowed'])
            self.assertEqual(diag.read_bundle(Path(report['bundle']))['chromium'],PLAYWRIGHT_EXE)

    def test_outer_timeout_never_claims_job_empty_or_echoes_partial_raw_output(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
            bundle=diag.prepare_bundle()
            error=subprocess.TimeoutExpired('synthetic',46,output=b'DO_NOT_LEAK',stderr=b'DO_NOT_LEAK')
            with patch.object(self.cli.subprocess,'run',side_effect=error) as execute,redirect_stdout(io.StringIO()) as output:
                code=self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only'])
            self.assertEqual(code,2);report=json.loads(output.getvalue())
            self.assertFalse(report['job_empty']);self.assertFalse(report['production_launch_allowed'])
            self.assertTrue((bundle/'watchdog-report.json').exists())
            self.assertTrue((bundle/'active-lease.json').exists())
            self.assertEqual(json.loads((bundle/'active-lease.json').read_text())['state'],'uncertain')
            self.assertEqual(execute.call_args.kwargs['stdin'],subprocess.DEVNULL)
            self.assertEqual(execute.call_args.kwargs['timeout'],46)
            self.assertNotIn('DO_NOT_LEAK',output.getvalue())

    def test_watchdog_records_selected_mode_without_raw_output_for_both_modes(self):
        for mode in diag.ENVIRONMENT_MODES:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                bundle=diag.prepare_bundle(environment_mode=mode)
                timeout=subprocess.TimeoutExpired('synthetic',46,output=b'DO_NOT_LEAK_ENVIRONMENT')
                with patch.object(self.cli.subprocess,'run',side_effect=timeout),redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only']),2)
                value=json.loads(output.getvalue());self.assertEqual(value['environment_mode'],mode)
                self.assertFalse(value['cleanup_verified']);self.assertFalse(value['production_launch_allowed'])
                lease=json.loads((bundle/'active-lease.json').read_text());self.assertEqual(lease['environment_mode'],mode)
                self.assertNotIn('DO_NOT_LEAK',output.getvalue())

    def test_worker_cannot_report_different_environment_than_selected_bundle(self):
        for selected,returned in (('minimal','windows_standard'),('windows_standard','minimal')):
            with self.subTest(selected=selected),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                expected_bundle=diag.prepare_bundle(environment_mode=selected)
                result_bundle=diag.prepare_bundle(environment_mode=returned)
                clock=FakeClock();backend=FakeBackend(clock)
                result=diag.run_diagnostic(result_bundle,approved_chromium_sha256='a'*64,
                                           acknowledge_diagnostic_only=True,
                                           _backend_factory=lambda:backend,_monotonic=clock)
                with patch.object(self.cli.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(result))) as execute,redirect_stdout(io.StringIO()) as output:
                    code=self.cli.main(['run','--bundle',str(expected_bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only'])
                execute.assert_called_once();self.assertEqual(code,2)
                value=json.loads(output.getvalue());self.assertEqual(value['environment_mode'],selected)
                self.assertEqual(value['diagnostic_stage'],'worker_report_invalid')

    def test_cli_rejects_arbitrary_url_option(self):
        with redirect_stdout(io.StringIO()),patch('sys.stderr',new=io.StringIO()),self.assertRaises(SystemExit) as error:
            self.cli.main(['prepare','--url','https://example.com'])
        self.assertEqual(error.exception.code,2)

    def test_worker_denial_retains_safe_stage_without_forwarding_unknown_fields(self):
        with tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
            bundle=diag.prepare_bundle()
            denial={'mode':'synthetic_diagnostic_only','status':'denied','isolation_verified':False,
                    'environment_mode':'minimal',
                    'job_launch_mode':'job_list',
                    'logging_mode':'disabled',
                    'production_launch_allowed':False,'diagnostic_stage':'standard_operator_identity_required',
                    'code':5,'raw':'DO_NOT_LEAK'}
            with patch.object(self.cli.subprocess,'run',return_value=Mock(returncode=2,stdout=json.dumps(denial))),redirect_stdout(io.StringIO()) as output:
                code=self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only'])
            self.assertEqual(code,2);self.assertNotIn('DO_NOT_LEAK',output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['diagnostic_stage'],'standard_operator_identity_required')

    def test_malformed_worker_output_and_duplicate_claims_fail_closed(self):
        for raw in ('DO_NOT_LEAK','{"mode":"synthetic_diagnostic_only","mode":"DO_NOT_LEAK"}', 'x'*65537):
            with self.subTest(size=len(raw)),tempfile.TemporaryDirectory() as root,patch.object(diag,'WORKSPACE',Path(root)):
                bundle=diag.prepare_bundle()
                with patch.object(self.cli.subprocess,'run',return_value=Mock(returncode=0,stdout=raw)),redirect_stdout(io.StringIO()) as output:
                    code=self.cli.main(['run','--bundle',str(bundle),'--approved-chromium-sha256','a'*64,'--acknowledge-diagnostic-only'])
                self.assertEqual(code,2);self.assertNotIn('DO_NOT_LEAK',output.getvalue())
                self.assertFalse(json.loads(output.getvalue())['production_launch_allowed'])


@unittest.skipUnless(os.name=='nt','Win32 diagnostics require Windows')
class NativeDiagnosticTests(unittest.TestCase):
    def backend(self):
        from jarvis.experimental.chromium_diagnostic_win32 import WindowsDiagnostic
        return WindowsDiagnostic()

    def test_real_current_token_read_only_no_chromium(self):
        backend=self.backend();identity=backend.operator_identity()
        self.assertTrue(identity['sid'].startswith('S-'));self.assertIs(type(identity['elevated']),bool)
        self.assertFalse(backend.created);self.assertFalse(backend.handles)
        self.assertEqual(backend.c.sizeof(backend.StartupEx),112 if backend.c.sizeof(backend.c.c_void_p)==8 else 72)

    @contextmanager
    def observation_fixture(self):
        backend=self.backend();backend.job=101;backend.root_sid=OPERATOR
        backend.observation_started=0;backend.chromium=diag.DEFAULT_CHROMIUM
        clock=FakeClock();state={'handle':201,'birth':10,'exited':set(),'codes':{201:0xc0000005,202:100}}
        def member(handle,job,output):
            self.assertEqual(job,101)
            backend.c.cast(output,backend.c.POINTER(backend.w.BOOL)).contents.value=True
            return True
        def exit_code(handle,output):
            backend.c.cast(output,backend.c.POINTER(backend.w.DWORD)).contents.value=state['codes'][handle]
            return True
        with ExitStack() as patches:
            for name,value in {
                'open_process':Mock(side_effect=lambda *args:state['handle']),
                'creation_time':Mock(side_effect=lambda handle:state['birth']),
                'in_job':Mock(side_effect=member),
                'identity':Mock(return_value={'sid':OPERATOR,'elevated':False}),
                'process_type':Mock(return_value='network-service'),
                'wait_handle':Mock(side_effect=lambda handle,ms:0 if handle in state['exited'] else 258),
                'get_exit':Mock(side_effect=exit_code),'close':Mock(return_value=True),
            }.items():patches.enter_context(patch.object(backend,name,value))
            patches.enter_context(patch('jarvis.experimental.chromium_diagnostic_win32.time.monotonic',clock))
            try:yield backend,clock,state
            finally:backend.handles.clear();backend.tracked.clear()

    def test_retained_handles_ignore_late_pid_packets_and_separate_generations(self):
        with self.observation_fixture() as (backend,clock,state):
            first=backend.track(123);backend.open_process.assert_called_once_with(0x101000,False,123)
            self.assertTrue(first.instance_verified);self.assertEqual(first.process_type,'network-service')
            backend.poll_tracked();backend.get_exit.assert_not_called()
            state['exited'].add(201);clock.now=.125;backend.poll_tracked()
            self.assertEqual((first.exit_code,first.exit_observed_ms,first.exit_phase),(0xc0000005,125,'before_cleanup'))
            state.update(handle=202,birth=20)
            second=backend.track(123);self.assertIsNot(first,second)
            backend.port=102
            # Even ABNORMAL_EXIT with this PID must not mark the new process.
            with patch.object(backend,'events',side_effect=self.event_source(backend,[(8,1,123),(7,1,123)])):
                backend.drain_events()
            self.assertFalse(second.exited);self.assertIsNone(second.exit_code)
            # A duplicate discovery resolves to the SAME birth, even after exit.
            self.assertIs(backend.track(123),second);self.assertEqual(len(backend.ledger.facts),2)
            self.assertEqual(set(backend.tracked),{0,1})
            backend.cleanup_started=True;clock.now=.2;state['exited'].add(202);backend.poll_tracked()
            self.assertEqual((second.exit_code,second.exit_observed_ms,second.exit_phase),(100,200,'cleanup_window'))

    def test_exit_code_259_is_only_read_after_signal_and_query_failure_stays_unknown(self):
        for failure in (False,True):
            with self.subTest(failure=failure),self.observation_fixture() as (backend,clock,state):
                fact=backend.track(123);state['codes'][201]=259
                backend.poll_tracked();self.assertFalse(fact.exited);backend.get_exit.assert_not_called()
                state['exited'].add(201)
                with patch.object(backend,'get_exit',return_value=False) if failure else ExitStack():backend.poll_tracked()
                self.assertTrue(fact.exited);self.assertEqual(fact.exit_code,None if failure else 259)

    def test_unverified_or_inaccessible_process_never_produces_exit_or_type_evidence(self):
        for failure in ('open','birth','token','membership','wait'):
            with self.subTest(failure=failure),self.observation_fixture() as (backend,clock,state):
                if failure=='open':backend.open_process.return_value=0;backend.open_process.side_effect=None
                elif failure=='birth':backend.creation_time.side_effect=diag.DiagnosticError('process_times',5)
                elif failure=='token':backend.identity.side_effect=diag.DiagnosticError('token_open',5)
                elif failure=='membership':backend.in_job.return_value=False;backend.in_job.side_effect=None
                if failure=='birth':
                    with self.assertRaises(diag.DiagnosticError):backend.track(123)
                    self.assertFalse(backend.ledger.facts);backend.close.assert_called_once_with(201)
                    continue
                fact=backend.track(123)
                if failure=='wait':backend.wait_handle.side_effect=None;backend.wait_handle.return_value=0xffffffff
                else:state['exited'].add(201)
                backend.poll_tracked()
                backend.get_exit.assert_not_called()
                if fact is not None:self.assertIsNone(fact.exit_code);self.assertFalse(fact.exited)
                if failure!='wait':backend.process_type.assert_not_called()

    def test_finish_observes_exit_before_termination_and_closes_retained_handles_on_failure(self):
        for terminate_ok in (True,False):
            with self.subTest(terminate_ok=terminate_ok),self.observation_fixture() as (backend,clock,state):
                first=backend.track(123);state.update(handle=202,birth=20)
                second=backend.track(456);state['exited'].add(201);backend.port=102
                def terminate(job,code):
                    self.assertTrue(first.exited);self.assertEqual(first.exit_phase,'before_cleanup')
                    self.assertTrue(backend.cleanup_started);self.assertEqual(code,100)
                    state['exited'].add(202);return terminate_ok
                def accounting(job,kind,output,size,returned):
                    value=backend.c.cast(output,backend.c.POINTER(backend.Accounting)).contents
                    value.active=0;value.total=2;return True
                with patch.object(backend,'terminate_job',side_effect=terminate),patch.object(backend,'query_job',side_effect=accounting),patch.object(backend,'drain_events',return_value=[]):
                    result=backend.finish(100)
                self.assertEqual(second.exit_phase,'cleanup_window');self.assertEqual(second.exit_code,100)
                self.assertTrue(result['inventory_reconciled']);self.assertTrue(result['handles_closed'])
                self.assertEqual(bool(result['diagnostics']),not terminate_ok)
                self.assertFalse(backend.tracked);self.assertFalse(backend.handles)
                self.assertEqual(backend.close.call_args_list,[unittest.mock.call(202),unittest.mock.call(201)])

    def test_type_query_is_bounded_transient_and_rejects_untrusted_native_buffers(self):
        for failure in ('none','unavailable','denied','image','size','pointer','length','null','argv'):
            with self.subTest(failure=failure):
                backend=self.backend();backend.chromium=diag.DEFAULT_CHROMIUM;c=backend.c;buffers=[]
                def image(handle,flags,buffer,size):
                    buffer.value='DO_NOT_LEAK.exe' if failure=='image' else diag.DEFAULT_CHROMIUM
                    return True
                def query(handle,kind,buffer,size,returned):
                    self.assertEqual((handle,kind,size),(201,60,65536));buffers.append(buffer)
                    if failure=='denied':return -1073741790
                    raw=('chrome --type=utility --utility-sub-type=network.mojom.NetworkService '
                         '--secret=DO_NOT_LEAK'+ ('\0hidden' if failure=='null' else '')).encode('utf-16le')
                    header=backend.UnicodeString.from_buffer(buffer);base=c.addressof(buffer)
                    header.length=len(raw);header.maximum=len(raw);header.buffer=base+c.sizeof(header)
                    c.memmove(header.buffer,raw,len(raw))
                    if failure=='pointer':header.buffer=1
                    if failure=='length':header.length=1
                    c.cast(returned,c.POINTER(backend.w.DWORD)).contents.value=65537 if failure=='size' else c.sizeof(header)+len(raw)
                    return 0
                argv=(c.c_wchar_p*4)('chrome','--type=utility','--utility-sub-type=network.mojom.NetworkService','--secret=DO_NOT_LEAK')
                def parsed(line,count):
                    c.cast(count,c.POINTER(c.c_int)).contents.value=4
                    return None if failure=='argv' else argv
                with patch.object(backend,'image_name',side_effect=image),patch.object(backend,'query_command',None if failure=='unavailable' else Mock(side_effect=query)),patch.object(backend,'argv',side_effect=parsed),patch.object(backend,'free',return_value=None) as free:
                    observed=backend.process_type(201)
                self.assertEqual(observed,'network-service' if failure=='none' else 'unknown')
                self.assertNotIn('DO_NOT_LEAK',observed)
                for buffer in buffers:self.assertEqual(buffer.raw,b'\0'*65536)
                self.assertEqual(free.call_count,int(failure=='none'))

    def test_native_start_passes_only_stdio_handles_and_assigns_before_resume(self):
        snapshots={}
        for mode in diag.ENVIRONMENT_MODES:
            with self.subTest(mode=mode):snapshots[mode]=self.native_start_snapshot(mode)
        minimal=snapshots['minimal'];expanded=snapshots['windows_standard']
        self.assertEqual({key:value for key,value in minimal.items() if key!='environment'},
                         {key:value for key,value in expanded.items() if key!='environment'})
        self.assertEqual(len(minimal['environment']),8)
        for key,value in minimal['environment'].items():self.assertEqual(expanded['environment'][key],value)
        self.assertNotIn('PROGRAMDATA',minimal['environment'])
        self.assertEqual(expanded['environment']['PROGRAMDATA'],WINDOWS_ENVIRONMENT['PROGRAMDATA'])

    def test_verbose_native_start_preserves_minimal_job_limits_and_inherited_handles(self):
        with self.native_launch_fixture() as (backend,session,snapshot,order,initializations):
            backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,logging_mode='verbose')
            backend.pin_directory.assert_any_call(session/'logs')
            backend.create_dir.assert_any_call(str(session/'logs'),None)
            backend.pin_runtime.assert_called_once_with(diag.DEFAULT_CHROMIUM,'a'*64)
            self.assertEqual(snapshot['command'],subprocess.list2cmdline(diag.command(diag.DEFAULT_CHROMIUM,session,logging_mode='verbose')))
            self.assertEqual(len(snapshot['environment']),8)
            self.assertNotIn('CHROME_LOG_FILE',snapshot['environment'])
            self.assertEqual(snapshot['creation_jobs'],[101]);self.assertEqual(snapshot['stdio'],(103,104,105))
            self.assertEqual(snapshot['flags'],diag.PROCESS_CREATION_FLAGS)
            self.assertTrue(diag.job_limits_match(backend.job_diagnostics['supervisor_limits']))
            backend.resume_thread.assert_not_called()
            self.assertEqual(order,['creation_job_list','create_suspended_in_job','verify_root'])

    def test_verbose_native_rejects_other_contexts_and_log_directory_failure_before_creation(self):
        for environment,job in (('windows_standard','job_list'),('minimal','guarded_assign')):
            with self.subTest(environment=environment,job=job),self.native_launch_fixture() as (backend,session,*unused):
                with self.assertRaisesRegex(diag.DiagnosticError,'logging_requires_minimal_job_list'):
                    backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,environment_mode=environment,
                                  job_launch_mode=job,logging_mode='verbose')
                backend.create_process.assert_not_called();backend.pin_runtime.assert_not_called()
        with self.native_launch_fixture() as (backend,session,*unused):
            backend.create_dir.side_effect=lambda path,security:Path(path).name!='logs'
            with self.assertRaisesRegex(diag.DiagnosticError,'session_subdirectory'):
                backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,logging_mode='verbose')
            backend.create_process.assert_not_called();backend.resume_thread.assert_not_called()

    def test_verbose_log_threshold_stops_monitoring_without_reading_log_contents(self):
        backend=self.backend();backend.logging_mode='verbose'
        with tempfile.TemporaryDirectory() as root:
            backend.session=Path(root);(backend.session/'logs').mkdir()
            for name in ('dom.txt','stderr.txt'):(backend.session/name).write_bytes(b'')
            log=diag.internal_log_path(backend.session)
            self.assertFalse(backend.output_exceeded())
            log.write_bytes(b'x'*(diag.MAX_INTERNAL_LOG+1))
            with self.assertRaisesRegex(diag.DiagnosticError,'internal_log_limit'):backend.output_exceeded()
            backend.logging_mode='disabled'
            with patch.object(diag,'_open_internal_log',side_effect=AssertionError('logging disabled')):
                self.assertFalse(backend.output_exceeded())

    def test_native_log_reader_rejects_changed_final_path_before_read_and_closes_handle(self):
        import ctypes as c
        with tempfile.TemporaryDirectory() as root:
            session=Path(root);(session/'logs').mkdir();diag.internal_log_path(session).write_bytes(LOG_BYTES)
            kernel=Mock();kernel.CreateFileW.return_value=100
            def final(handle,buffer,size,flags):buffer.value=r'\\?\C:\DO_NOT_LEAK\other.log';return len(buffer.value)
            kernel.GetFinalPathNameByHandleW.side_effect=final
            with patch.object(c,'WinDLL',return_value=kernel),patch('msvcrt.open_osfhandle') as descriptor:
                summary=diag.internal_log_summary(session,'verbose')
            descriptor.assert_not_called();kernel.CloseHandle.assert_called_once_with(100)
            self.assertEqual(summary['presence'],'unreadable');self.assertNotIn('DO_NOT_LEAK',json.dumps(summary))

    def test_verbose_command_round_trips_windows_argument_quoting(self):
        import ctypes as c
        from ctypes import wintypes as w
        shell=c.WinDLL('shell32',use_last_error=True)
        parse=shell.CommandLineToArgvW;parse.restype=c.POINTER(w.LPWSTR)
        parse.argtypes=[w.LPCWSTR,c.POINTER(c.c_int)]
        kernel=c.WinDLL('kernel32',use_last_error=True)
        free=kernel.LocalFree;free.restype=c.c_void_p;free.argtypes=[c.c_void_p]
        arguments=diag.command(diag.DEFAULT_CHROMIUM,Path(r'E:\JARVIS\synthetic session with spaces'),logging_mode='verbose')
        count=c.c_int();parsed=parse(subprocess.list2cmdline(arguments),c.byref(count))
        self.assertTrue(parsed)
        try:self.assertEqual(list(parsed[:count.value]),arguments)
        finally:self.assertFalse(free(parsed))

    def native_start_snapshot(self, mode, job_launch_mode='job_list'):
        with self.native_launch_fixture(job_launch_mode=job_launch_mode) as (backend,session,snapshot,order,initializations):
            backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,environment_mode=mode,job_launch_mode=job_launch_mode)
            backend.pin_runtime.assert_called_once_with(diag.DEFAULT_CHROMIUM,'a'*64)
            backend.resume_thread.assert_not_called()
            expected=['creation_job_list','create_suspended_in_job']
            if job_launch_mode!='job_list':expected.append('verify_guard')
            if job_launch_mode=='guarded_assign':expected.extend(('verify_supervisor_absent','assign_supervisor'))
            expected.append('verify_root');self.assertEqual(order,expected)
            self.assertEqual(initializations,[False,True])
            backend.delete_attributes.assert_called_once();backend.pin_directory.assert_any_call(session)
            self.assertEqual(len(backend.handles),7+(job_launch_mode!='job_list'))
            backend.resume();backend.resume_thread.assert_called_once_with(107)
            snapshot['audit']=backend.job_diagnostics
        return snapshot

    def test_native_guarded_methods_keep_identical_limits_and_verify_before_resume(self):
        for environment in diag.ENVIRONMENT_MODES:
            with self.subTest(environment=environment):
                atomic=self.native_start_snapshot(environment,'guarded_job_list')
                explicit=self.native_start_snapshot(environment,'guarded_assign')
                self.assertEqual(atomic['creation_jobs'],[100,101])
                self.assertEqual(explicit['creation_jobs'],[100])
                for key in ('executable','command','cwd','flags','stdio','environment','job_limits'):
                    self.assertEqual(atomic[key],explicit[key])

    def test_native_launch_failures_never_resume_and_always_close_owned_jobs(self):
        common=('supervisor_create','supervisor_limits_set','supervisor_limits_query',
                'supervisor_ui_query','supervisor_limits_verify','port_create','port_associate',
                'job_list_attribute','process_create','root_verification')
        guard=('guard_create','guard_limits_set','guard_limits_query','guard_ui_query',
               'guard_limits_verify','guard_port_associate','guard_membership','guard_membership_mismatch')
        assignment=('supervisor_absent_before_assign','supervisor_already_present','supervisor_assign')
        post_create={'root_verification','guard_membership','guard_membership_mismatch',*assignment}
        for mode in diag.JOB_LAUNCH_MODES:
            failures=common+(guard if mode!='job_list' else ())+(assignment if mode=='guarded_assign' else ())
            for failure in failures:
                with self.subTest(mode=mode,failure=failure),self.native_launch_fixture(job_launch_mode=mode,failure=failure) as (backend,session,snapshot,order,initializations):
                    with self.assertRaises(diag.DiagnosticError):
                        backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,job_launch_mode=mode)
                    self.assertFalse(backend.ready)
                    with self.assertRaisesRegex(diag.DiagnosticError,'root_not_ready'):backend.resume()
                    backend.resume_thread.assert_not_called()
                    self.assertEqual(backend.created,failure in post_create)
                    owned=list(backend.handles);jobs=[job for job in (backend.job,backend.guard) if job]
                    result=backend.finish(100)
                    self.assertTrue(result['job_empty']);self.assertTrue(result['root_stopped'])
                    self.assertTrue(result['handles_closed']);self.assertFalse(backend.handles)
                    self.assertEqual([call.args for call in backend.close.call_args_list],[(h,) for h in reversed(owned)])
                    self.assertEqual([call.args for call in backend.terminate_job.call_args_list],[(job,100) for job in jobs])
                    if mode!='job_list' and failure in post_create:
                        self.assertTrue(backend.job_diagnostics['guard_empty'])
                        self.assertEqual(backend.job_diagnostics['final_accounting']['guard']['total'],1)

    def test_ambient_job_failure_denies_before_creating_browser_or_own_jobs(self):
        for failure in ('worker_job_query','ambient_limits_query','ambient_ui_query','ambient_ui_verify'):
            with self.subTest(failure=failure),self.native_launch_fixture(failure=failure) as (backend,session,*unused):
                with self.assertRaises(diag.DiagnosticError):
                    backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR)
                backend.create_process.assert_not_called();backend.create_job.assert_not_called()
                backend.pin_runtime.assert_not_called()

    def test_resume_failure_cannot_be_retried_or_report_a_stale_win32_error(self):
        for previous,expected in ((0xffffffff,5),(0,0),(2,0)):
            with self.subTest(previous=previous),self.native_launch_fixture(job_launch_mode='guarded_assign') as (backend,session,*unused):
                backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,job_launch_mode='guarded_assign')
                backend.resume_thread.return_value=previous;backend.c.set_last_error(5)
                with self.assertRaisesRegex(diag.DiagnosticError,'resume_thread') as error:backend.resume()
                self.assertEqual(error.exception.code,expected)
                self.assertFalse(backend.ready)
                with self.assertRaisesRegex(diag.DiagnosticError,'root_not_ready'):backend.resume()
                self.assertTrue(backend.finish(100)['job_empty'])

    def test_guard_cleanup_requires_independent_accounting_and_handle_closure(self):
        for mode in ('guarded_job_list','guarded_assign'):
            for failure in ('guard_accounting','guard_still_active','close','terminate'):
                with self.subTest(mode=mode,failure=failure),self.native_launch_fixture(job_launch_mode=mode,failure=failure) as (backend,session,*unused):
                    backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,job_launch_mode=mode)
                    if failure=='close':backend.close.return_value=False
                    if failure=='terminate':backend.terminate_job.return_value=False
                    # Exercise accounting rather than racing a real 5 ms deadline.
                    ticks=iter(index/1000 for index in range(100))
                    with patch('jarvis.experimental.chromium_diagnostic_win32.time.monotonic',side_effect=lambda:next(ticks)),patch('jarvis.experimental.chromium_diagnostic_win32.time.sleep'):
                        result=backend.finish(5)
                    self.assertEqual(result['job_empty'],failure not in ('guard_accounting','guard_still_active'))
                    self.assertEqual(result['handles_closed'],failure!='close')
                    self.assertTrue(result['diagnostics'] or failure=='guard_still_active')
                    self.assertFalse(backend.handles)

    def test_failed_assignment_retains_guard_and_terminates_only_owned_root_handle(self):
        with self.native_launch_fixture(job_launch_mode='guarded_assign',failure='supervisor_assign') as (backend,session,*unused):
            with self.assertRaisesRegex(diag.DiagnosticError,'supervisor_assign'):
                backend.start(diag.DEFAULT_CHROMIUM,session,'a'*64,OPERATOR,job_launch_mode='guarded_assign')
            backend.root_exited.side_effect=[False,True]
            result=backend.finish(100)
            backend.terminate_process.assert_called_once_with(106,100)
            backend.open_process.assert_not_called()
            backend.resume_thread.assert_not_called()
            self.assertTrue(result['job_empty']);self.assertTrue(result['root_stopped'])
            self.assertTrue(backend.job_diagnostics['guard_empty'])
            self.assertFalse(result['inventory_reconciled'])

    @contextmanager
    def native_launch_fixture(self, *, job_launch_mode='job_list', failure=None):
        backend=self.backend();c=backend.c;w=backend.w;order=[];initializations=[]
        snapshot={};session=diag.WORKSPACE/('chromium-diagnostic-review-'+'a'*32)/'session'
        guarded=job_launch_mode!='job_list';roles={101:'supervisor',100:'guard',None:'ambient'}
        def denied(stage):
            if failure==stage:c.set_last_error(5);return True
            return False
        def create_job(security,name):
            self.assertIsNone(security);self.assertIsNone(name)
            role='guard' if guarded and backend.guard is None else 'supervisor'
            if denied(role+'_create'):return 0
            return 100 if role=='guard' else 101
        def limits(job,kind,buffer,size):
            self.assertIn(job,(100,101))
            if kind==9:
                value=c.cast(buffer,c.POINTER(backend.Limits)).contents
                self.assertEqual((value.basic.flags,value.basic.active),(0x2008,64))
                snapshot.setdefault('job_limits',{})[job]=bytes(value)
                if denied(roles[job]+'_limits_set'):return False
            else:
                self.assertEqual(kind,7)
                value=c.cast(buffer,c.POINTER(backend.Port)).contents
                self.assertEqual((value.key,value.port),(1 if job==101 else 2,102))
                if denied('port_associate' if job==101 else 'guard_port_associate'):return False
            return True
        def query(job,kind,buffer,size,returned):
            role=roles[job]
            if kind==9:
                if denied(role+'_limits_query'):return False
                value=c.cast(buffer,c.POINTER(backend.Limits)).contents
                value.basic.flags=0x2008;value.basic.active=64
                if failure==role+'_limits_verify':value.basic.flags|=0x800  # forbidden breakaway
            elif kind==4:
                if denied(role+'_ui_query'):return False
                c.cast(buffer,c.POINTER(w.DWORD)).contents.value=1 if failure=='ambient_ui_verify' else 0
            else:
                self.assertEqual(kind,1)
                if denied('guard_accounting' if role=='guard' else 'job_accounting'):return False
                value=c.cast(buffer,c.POINTER(backend.Accounting)).contents
                value.active=1 if failure=='guard_still_active' and role=='guard' else 0
                value.total=int(backend.created and (role=='guard' or 'verify_root' in order))
            return True
        def member(process,job,output):
            if job is None:
                if denied('worker_job_query'):return False
                c.cast(output,c.POINTER(w.BOOL)).contents.value=bool(failure and failure.startswith('ambient_'))
            else:
                self.assertEqual(process,106)
                if job==100:
                    order.append('verify_guard')
                    if denied('guard_membership'):return False
                    c.cast(output,c.POINTER(w.BOOL)).contents.value=failure!='guard_membership_mismatch'
                else:
                    self.assertEqual(job,101);order.append('verify_supervisor_absent')
                    if denied('supervisor_absent_before_assign'):return False
                    c.cast(output,c.POINTER(w.BOOL)).contents.value=failure=='supervisor_already_present'
            return True
        def assign(job,process):
            self.assertEqual((job,process),(101,106))
            self.assertEqual(order,['creation_job_list','create_suspended_in_job','verify_guard','verify_supervisor_absent'])
            order.append('assign_supervisor');return not denied('supervisor_assign')
        def initialize(buffer,count,flags,size):
            self.assertEqual(count,2)
            c.cast(size,c.POINTER(c.c_size_t)).contents.value=128
            initializations.append(buffer is not None)
            if buffer is None:c.set_last_error(122);return False
            return True
        def update(attributes,flags,key,handles,size,previous,returned):
            if key==0x20002:
                self.assertEqual(list(handles),[103,104,105]);self.assertEqual(size,3*c.sizeof(w.HANDLE))
            else:
                self.assertEqual(key,0x2000d)
                expected=([101] if not guarded else [100,101] if job_launch_mode=='guarded_job_list' else [100])
                self.assertEqual(list(handles),expected)
                self.assertEqual(size,len(expected)*c.sizeof(w.HANDLE));order.append('creation_job_list')
                snapshot['creation_jobs']=list(handles)
                if denied('job_list_attribute'):return False
            return True
        def windows(buffer,size):buffer.value=r'C:\Windows';return len(buffer.value)
        def created(executable,line,process_security,thread_security,inherit,flags,environment,cwd,startup,process):
            self.assertEqual(executable,diag.DEFAULT_CHROMIUM)
            self.assertTrue(inherit);self.assertEqual(flags,0x08080404)
            if denied('process_create'):return False
            info=c.cast(startup,c.POINTER(backend.StartupEx)).contents.startup
            self.assertEqual((info.stdin,info.stdout,info.stderr),(103,104,105))
            self.assertEqual(info.cb,c.sizeof(backend.StartupEx));self.assertEqual(info.flags,0x100)
            block=''.join(environment[:])
            self.assertNotIn('DO_NOT_LEAK',block);self.assertNotIn('API_KEY',block)
            self.assertIn('TEMP='+str(Path(cwd)/'Temp'),block)
            self.assertIn(diag.DATA_URL,line.value);self.assertNotIn('--no-sandbox',line.value)
            self.assertTrue(block.endswith('\0\0'))
            entries=[entry.split('=',1) for entry in block.rstrip('\0').split('\0')]
            self.assertEqual([key for key,value in entries],sorted((key for key,value in entries),key=str.upper))
            snapshot.update(executable=executable,command=line.value,cwd=cwd,flags=flags,
                            stdio=(info.stdin,info.stdout,info.stderr),environment=dict(entries))
            result=c.cast(process,c.POINTER(backend.ProcessInfo)).contents
            result.process=106;result.thread=107;result.pid=1234;result.tid=1235
            self.assertEqual(order,['creation_job_list'])
            order.append('create_suspended_in_job');return True
        def inspect(fact,handle):
            self.assertEqual(handle,106);order.append('verify_root');fact.identity=fact.membership='verified'
            if failure=='root_verification':fact.membership='unknown'
        with ExitStack() as patches:
            for name,override in {
                'pin_runtime':Mock(), 'pin_directory':Mock(), 'create_dir':Mock(return_value=True),
                'create_job':Mock(side_effect=create_job),'create_port':Mock(side_effect=lambda *args:0 if denied('port_create') else 102),
                'create_file':Mock(side_effect=[103,104,105]),'set_job':Mock(side_effect=limits),
                'query_job':Mock(side_effect=query),'in_job':Mock(side_effect=member),'assign_job':Mock(side_effect=assign),
                'initialize':Mock(side_effect=initialize),'update':Mock(side_effect=update),
                'windows_dir':Mock(side_effect=windows),'create_process':Mock(side_effect=created),
                'delete_attributes':Mock(),
                'open_process':Mock(side_effect=AssertionError('no PID-based termination')),
                'inspect':Mock(side_effect=inspect),'resume_thread':Mock(return_value=1),
                'creation_time':Mock(return_value=1),'poll_tracked':Mock(),
                'terminate_job':Mock(return_value=True),'terminate_process':Mock(return_value=True),
                'close':Mock(return_value=True),'root_exited':Mock(return_value=True),'drain_events':Mock(return_value=[])
            }.items():patches.enter_context(patch.object(backend,name,override))
            patches.enter_context(patch.dict(os.environ,dict(WINDOWS_ENVIRONMENT,**SENSITIVE_ENVIRONMENT)))
            try:yield backend,session,snapshot,order,initializations
            finally:backend.handles.clear()  # All handles here were synthetic integers.

    def test_invalid_native_environment_mode_denies_before_any_runtime_access(self):
        backend=self.backend()
        with patch.object(backend,'pin_runtime') as runtime,patch.object(backend,'create_process') as create:
            with self.assertRaisesRegex(diag.DiagnosticError,'invalid_environment_mode'):
                backend.start(diag.DEFAULT_CHROMIUM,diag.WORKSPACE/'session','a'*64,OPERATOR,environment_mode='inherit')
        runtime.assert_not_called();create.assert_not_called();self.assertFalse(backend.handles)

    def test_runtime_hash_mismatch_is_detected_with_no_write_or_delete_sharing(self):
        for executable in (diag.DEFAULT_CHROMIUM,PLAYWRIGHT_EXE):
            with self.subTest(executable=executable):
                backend=self.backend();c=backend.c;w=backend.w
                def final(handle,buffer,size,flags):
                    buffer.value='\\\\?\\'+executable;return len(buffer.value)
                def read(handle,buffer,size,count,overlapped):
                    c.cast(count,c.POINTER(w.DWORD)).contents.value=0;return True
                with patch('jarvis.experimental.chromium_diagnostic_win32.no_reparse'),patch.object(backend,'create_file',return_value=101) as opened,patch.object(backend,'final_path',side_effect=final),patch.object(backend,'read_file',side_effect=read),self.assertRaisesRegex(diag.DiagnosticError,'runtime_hash_mismatch'):
                    backend.pin_runtime(executable,'a'*64)
                self.assertEqual(opened.call_args.args[1:3],(0xa0000000,1))
                backend.handles.clear()

    def test_directory_pin_rejects_reparse_without_write_or_delete_access(self):
        backend=self.backend();c=backend.c
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)
            def final(handle,buffer,size,flags):buffer.value='\\\\?\\'+str(path);return len(buffer.value)
            def info(handle,kind,buffer,size):buffer[0]=0x410;return True
            with patch.object(backend,'create_file',return_value=101) as opened,patch.object(backend,'final_path',side_effect=final),patch.object(backend,'file_info',side_effect=info),self.assertRaisesRegex(diag.DiagnosticError,'directory_reparse'):
                backend.pin_directory(path)
            self.assertEqual(opened.call_args.args[1:3],(0x80,7))
        backend.handles.clear()

    def test_access_denied_remains_unknown_with_narrow_rights(self):
        for failure in ('open','token','job','mismatch'):
            with self.subTest(failure=failure):
                backend=self.backend();backend.job=101;backend.root_sid=OPERATOR
                def membership(handle,job,pointer):
                    backend.c.cast(pointer,backend.c.POINTER(backend.w.BOOL)).contents.value=True
                    return failure!='job'
                identity={'sid':OPERATOR if failure!='mismatch' else diag.RESTRICTED_SID,'elevated':False}
                with patch.object(backend,'open_process',return_value=0 if failure=='open' else 102) as opened,patch.object(backend,'in_job',side_effect=membership),patch.object(backend,'identity',side_effect=diag.DiagnosticError('token_open',5) if failure=='token' else None,return_value=identity),patch.object(backend,'close',return_value=True),patch.object(backend,'creation_time',return_value=1),patch.object(backend,'process_type',return_value='unknown'):
                    if failure=='mismatch':
                        with self.assertRaises(diag.DiagnosticError):backend.track(987654)
                    else:backend.track(987654)
                    opened.assert_called_once_with(0x101000,False,987654)
                if failure=='open':self.assertFalse(backend.ledger.facts);continue
                fact=backend.ledger.facts[0]
                if failure=='token':self.assertEqual(fact.identity,'unknown')
                if failure=='token':self.assertEqual(fact.token_error,5);self.assertEqual(fact.membership,'verified')
                if failure=='job':self.assertEqual(fact.identity,'verified');self.assertEqual(fact.membership,'unknown')
                backend.handles.clear();backend.tracked.clear()  # Synthetic handles only.

    def test_job_event_pid_reuse_and_unknown_key_are_bounded(self):
        backend=self.backend();backend.port=101
        entries=iter([(6,1,123),(7,1,123),(6,1,123),(7,1,123)])
        def events(port,message,key,pid,timeout):
            try:kind,key_value,pid_value=next(entries)
            except StopIteration:backend.c.set_last_error(258);return False
            backend.c.cast(message,backend.c.POINTER(backend.w.DWORD)).contents.value=kind
            backend.c.cast(key,backend.c.POINTER(backend.c.c_size_t)).contents.value=key_value
            backend.c.cast(pid,backend.c.POINTER(backend.c.c_void_p)).contents.value=pid_value
            return True
        with patch.object(backend,'events',side_effect=events),patch.object(backend,'open_process',return_value=0):backend.drain_events()
        self.assertEqual(len(backend.ledger.facts),0)
        self.assertTrue(backend.observation_gaps);self.assertFalse(backend.ledger.complete)

    def event_source(self,backend,entries):
        entries=iter(entries)
        def receive(port,message,key,pid,timeout):
            try:kind,source,process=next(entries)
            except StopIteration:backend.c.set_last_error(258);return False
            backend.c.cast(message,backend.c.POINTER(backend.w.DWORD)).contents.value=kind
            backend.c.cast(key,backend.c.POINTER(backend.c.c_size_t)).contents.value=source
            backend.c.cast(pid,backend.c.POINTER(backend.c.c_void_p)).contents.value=process
            return True
        return receive

    def test_guard_forwarded_events_are_separate_and_do_not_duplicate_inventory(self):
        backend=self.backend();backend.port=102;backend.guard=100
        entries=[(6,1,123),(6,2,123),(8,1,123),(8,2,123),(4,1,None),(4,2,None)]
        with patch.object(backend,'events',side_effect=self.event_source(backend,entries)),patch.object(backend,'open_process',return_value=0):
            backend.drain_events()
        self.assertEqual(len(backend.ledger.facts),0)
        for key in ('events','guard_events'):
            self.assertEqual(backend.job_diagnostics[key]['new_process'],1)
            self.assertEqual(backend.job_diagnostics[key]['abnormal_exit_process'],1)
            self.assertEqual(backend.job_diagnostics[key]['active_process_zero'],1)
        self.assertFalse(backend.job_diagnostics['events_complete'])

    def test_cleanup_drains_events_after_limit_and_reconciles_with_accounting(self):
        backend=self.backend();backend.port=102;backend.job=101;backend.guard=100
        backend.created=True;backend.process=106;backend.handles=[100,101,102,106]
        fact=backend.ledger.observe(123);fact.identity=fact.membership='verified'
        entries=[(3,1,None),(3,2,None),(7,1,123),(7,2,123),(4,1,None),(4,2,None)]
        def accounting(job,kind,buffer,size,returned):
            result=backend.c.cast(buffer,backend.c.POINTER(backend.Accounting)).contents
            result.active=0;result.total=1;return True
        with patch.object(backend,'events',side_effect=self.event_source(backend,entries)),patch.object(backend,'query_job',side_effect=accounting),patch.object(backend,'terminate_job',return_value=True),patch.object(backend,'root_exited',return_value=True),patch.object(backend,'close',return_value=True):
            result=backend.finish(100)
        self.assertTrue(result['job_empty']);self.assertFalse(result['inventory_reconciled'])
        self.assertFalse(fact.exited)  # A PID-only exit packet is never identity evidence.
        self.assertEqual(result['diagnostics'],[{'stage':'job_limit_event','code':3}]*2)
        self.assertEqual(backend.job_diagnostics['events']['active_process_limit'],1)
        self.assertEqual(backend.job_diagnostics['guard_events']['active_process_limit'],1)

    def test_event_key_unknown_message_counter_and_queue_are_bounded(self):
        for entries,stage in (([(6,99,123)],'job_event_key'),([(99,1,None)],'job_event_unknown'),
                              ([(3,1,None)],'job_limit_event'),([(4,1,None)]*257,'job_event_limit')):
            with self.subTest(stage=stage):
                backend=self.backend();backend.port=102
                with patch.object(backend,'events',side_effect=self.event_source(backend,entries)):
                    with self.assertRaisesRegex(diag.DiagnosticError,stage):backend.drain_events()
        backend=self.backend();backend.port=102
        backend.job_diagnostics['events']['active_process_zero']=65536
        with patch.object(backend,'events',side_effect=self.event_source(backend,[(4,1,None)])):
            with self.assertRaisesRegex(diag.DiagnosticError,'job_event_limit'):backend.drain_events()

    def test_cleanup_unknown_accounting_and_close_failure_fail_closed(self):
        for failure in ('none','accounting','close'):
            with self.subTest(failure=failure):
                backend=self.backend();backend.job=101;backend.process=102;backend.port=103
                backend.created=True;backend.handles=[101,102,103]
                fact=backend.ledger.observe(123);fact.identity=fact.membership='verified'
                def accounting(job,kind,pointer,size,needed):
                    if failure=='accounting':return False
                    value=backend.c.cast(pointer,backend.c.POINTER(backend.Accounting)).contents
                    value.active=0;value.total=1;return True
                with patch.object(backend,'terminate_job',return_value=True),patch.object(backend,'root_exited',return_value=True),patch.object(backend,'query_job',side_effect=accounting),patch.object(backend,'drain_events'),patch.object(backend,'close',return_value=failure!='close') as close:
                    result=backend.finish(100)
                self.assertFalse(backend.handles);self.assertEqual(close.call_count,3)
                self.assertEqual(result['job_empty'],failure!='accounting')
                self.assertEqual(result['handles_closed'],failure!='close')
                self.assertFalse(result['inventory_reconciled'])  # No retained/verified process object.

    def test_root_wait_failure_still_attempts_termination_of_our_suspended_root(self):
        backend=self.backend();backend.created=True;backend.process=101;backend.handles=[101]
        with patch.object(backend,'root_exited',side_effect=diag.DiagnosticError('root_wait',6)),patch.object(backend,'terminate_process',return_value=True) as terminate,patch.object(backend,'close',return_value=True):
            result=backend.finish(100)
        terminate.assert_called_once_with(101,100)
        self.assertFalse(result['root_stopped']);self.assertFalse(result['job_empty'])
        self.assertTrue(result['diagnostics'])


if __name__=='__main__':unittest.main()
