# Chromium under AppContainer: viability blocked, not network isolation

The experimental opt-in `run_chromium_appcontainer_probe` reuses the auxiliary
profile/STARTUPINFOEX/zero-capability launcher and kill-on-close Job Object.
No production file, existing Playwright module, permission evaluator, network
policy, firewall or loopback exemption is modified.

It stages only the cached Chromium executable, core DLL/data/pak assets, en-US
locale and side-by-side manifests into the profile it just created. This avoids
granting an AppContainer SID access to personal cache folders. No browser is
downloaded, no broad ACL is added, and the runtime copy is deleted with that
owned profile. A separate real DOM control proves this identical minimal
runtime set works outside AppContainer using the existing synthetic prototype.

Chromium receives an in-memory data: HTML fixture through its headless dump-dom
CLI. There is no debugging TCP port, sandbox bypass, insecure certificate flag
or network capability. Output/error handles are explicitly selected for
inheritance with PROC_THREAD_ATTRIBUTE_HANDLE_LIST; no unrelated handles are
intentionally inherited. A fixture splits the expected result marker in its
JavaScript source, so the serialized result element demonstrates actual script
execution rather than merely finding a string in the source.

The parent verifies the root token's TokenIsAppContainer, SID and capability
count while suspended and after Job assignment, before resuming. While running,
it samples Job process IDs, token facts, IsProcessInJob and working-set memory.
Inspection failures retain unknown fields/error numbers rather than guessing
identity. Sampling can miss short-lived processes, and Job enumeration does
not independently inventory processes created outside the Job. This is not an
exhaustive process-tree proof. The RAM peak is a lower-bound sampled sum of
working sets (including shared pages), not unique memory or GPU consumption.

Observed on this host with cached Chromium 145.0.7632.6:
- The initial relocation missed the versioned manifest: CreateProcessW failed
  with 14001 (side-by-side activation context). Including the existing manifest
  resolved this packaging defect without security changes.
- Windows then created/resumed Chromium in AppContainer with expected SID,
  zero capabilities and confirmed Job membership.
- It exited early with 2147483651 / 0x80000003 (STATUS_BREAKPOINT).
- No serialized result element or descendant process was observed.
- Approximate sampled working set was 9.8 MiB for this early-exiting process;
  this is NOT a measurement of a functioning browser's memory requirements.
- The identical relocated assets worked in the unrestricted synthetic control.
- No actionable permission-specific diagnostic was captured. The breakpoint
  alone does not establish which API, permission or Chromium assertion failed.

Do not loosen capabilities or disable Chromium's sandbox to turn this into a
success. Full initialization/DOM execution under AppContainer is currently
blocked. Further diagnosis would require a separately scoped native debugging
experiment; no additional permissions are granted automatically here.

Finally TerminateJobObject runs and active Job process IDs must reach zero;
handles close and DeleteAppContainerProfile deletes the exclusively owned
profile, including its temporary browser data/runtime. Any failure is returned
in cleanup_complete/remaining_resources. No recursive shell deletion is used.
The prior TCP/UDP auxiliary experiments remain available and inconclusive.

Tests explicitly distinguish a successful observation from an early exit or
timeout. A passing viability-outcome test means identity/measurement/cleanup
were verified, NOT that Chromium functioned or that networking was isolated.
