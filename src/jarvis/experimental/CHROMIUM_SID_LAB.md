# Restricted-account Chromium experiment

Experimental and not registered in production. `chromium_sid_lab.preflight`
requires the exact local standard account/SID and existing effective SID rule,
enabled firewall profiles, BFE and MpsSvc. No rule, account, ACL, desktop or
profile permissions are changed. There is no elevated or current-user fallback.

The reviewed interactive runner is `tools/experimental/run_sid_chromium_review.py`.
Operator credentials use hidden `getpass` input and one transient stdin transfer
to the native fixture. They are never argv, files or diagnostic output. Python
and .NET immutable strings do not guarantee zeroization against a debugger.
The launch boundary can later be replaced by trusted token provisioning without
changing browser authorization; no credential storage/service is implemented.

The fixture reuses SID-lab Win32 APIs: CreateProcessWithLogonW, suspended start,
verified standard TokenUser, non-breakaway kill-on-close Job, then resume.
Chromium retains its own sandbox, uses a fresh disposable profile, and receives
only fixed synthetic data: HTML. No debug port, network proxy, public URL or
loopback exemption is configured. `--dump-dom` captures DOM to own files through
explicit output handles. Script source strings alone are not execution evidence:
the parser requires the resulting body attribute and span text after JS click.

Process sampling checks descendant parent IDs, roles from local WMI (renderer,
GPU, network service when identifiable), token user/admin groups and membership
in the specific Job. Inaccessible, escaped or unexpected processes are reported;
inspection uncertainty prevents certifying whole-family cleanup. Sampling cannot
prove that every short-lived descendant was observed. Aggregate working set is
an approximate sampled peak; Job CPU counters are reported in milliseconds.
Job termination, root wait and handle closure are separate facts. A rule-lifetime
guard never permits removal when cleanup is uncertain. There is no rule deleter.

Stock Playwright exposes `connect(endpoint)` and `connect_over_cdp(endpoint_url)`;
there is no public adapter here for attaching to native cross-identity pipe
handles. Existing `launch()` would use the controller identity. This version
therefore tests dump-dom and JS programmatic click, NOT Playwright interaction.
A future pipe-aware launch adapter must preserve identity/Job checks and avoid
TCP/UDP debugging. Nothing here proves OS network isolation, including loopback.

## Actual run on 2026-10-12

Preflight succeeded. The interactive restricted launch returned `process_create`
Win32 5 (ERROR_ACCESS_DENIED), before process creation. Chromium, DOM, JS and
Playwright were NOT observed. Job empty and handles closed were confirmed.
Read-only ACL inspection showed the cached executable granted access to the
operator, Administrators, SYSTEM and sandbox principals, with no explicit grant
to the dedicated account or ordinary Users. This is compatible with the failure;
the Win32 error alone does not isolate which executable/ancestor/desktop access
check failed. No access grants, staging workaround or second launch was attempted.

Only own empty profiles are removed after confirmed cleanup. Nonempty profile,
launcher and sanitized result artifacts remain for operator review; no general
recursive cleanup or permission repair is performed. No measured browser RAM/CPU
is available when process creation fails. Native launcher/inspection branches
are compiled and tested with simulated reports, not claimed as live child proof.
