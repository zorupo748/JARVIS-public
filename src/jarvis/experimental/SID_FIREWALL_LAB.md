# Windows SID firewall laboratory — not production isolation

No operation here creates accounts, installs/removes rules, modifies firewall
profiles, grants loopback exemptions, changes ACLs or requests elevation.
`SIDBlockPlan.privileged_install_arguments()` returns a reviewable specification;
there is deliberately no installer or deleter. `LocalUser` uses a single-user
SDDL DACL (`D:(A;;CC;;;SID)`), not an executable path or username credential.

Read-only preparation:

1. The operator supplies an existing dedicated enabled LOCAL standard account
   name. `inspect_local_identity` verifies its SAM SID and indirect membership
   in Administrators using built-in AccountManagement. Unknown membership is an
   error; an administrator with a filtered token is not a standard account.
2. Construct `SIDBlockPlan` with a unique `jarvis-sid-lab-*` rule name. Review
   its future outbound Block/Any-profile/Any-protocol/Any-address specification.
3. `validate_effective_rule` reads ActiveStore, security/application/address/port
   filters, firewall profiles and BFE/MpsSvc. Missing, ambiguous or unexpected
   configuration fails closed. Exact SDDL comparison may conservatively reject
   equivalent descriptors. A matching rule is configuration evidence, not proof
   that loopback/UDP/IPv6 or all Windows traffic is blocked.

Later, separately authorized operator actions are required to provision the
account/rule and ensure minimal read/execute access to the helper. No automatic
ACL workaround, sandbox flag, elevation or broad directory grant is implemented.

Compile `tests/fixtures/sid_firewall_probe.cs` with the existing OS .NET compiler
into a temporary directory. Launch is opt-in via `run_account_probe`, only after
re-inspecting the account and effective rule. Supply credentials transiently from
trusted operator input, never a model or browser. They pass only over stdin to
the launcher, never command-line arguments, JSON, files or reports. Python/.NET
immutable strings cannot promise memory zeroization or concealment from a
privileged debugger. Do not enable transcript or credential logging.

The launcher uses CreateProcessWithLogonW with ZERO logon flags (no profile load,
no network-only credentials), starts suspended, assigns a non-breakaway
kill-on-close Job and verifies TokenUser/admin groups before resuming. The helper
starts children normally in the Job; each child verifies its own SID, all admin
group membership and Job membership before attempting a connection. This is
trusted-helper evidence, not exhaustive Chromium descendant inspection.

Supply 1–8 numeric controlled echo endpoints, only local/private addresses,
TCP/UDP and IPv4/IPv6. Never specify a public destination or DNS hostname. Set up
listeners under operator control; LAN listeners require a separately owned LAN
peer. `run_positive_controls` records controller SID and actual echoes; run it
before AND after the restricted helper. The controller SID must differ from the
blocked SID. All attempts use bounded waits and a fixed echo marker. UDP send
alone and timeouts are inconclusive. `classify_attempts` requires effective-rule,
identity and cleanup evidence plus successful controls before recognizing
`access_denied_observed`; even WSAEACCES is not proof the named rule caused it.
Any echo under the blocked identity disproves blocking for that tested path.

The launcher terminates the entire Job and verifies ActiveProcesses==0 before
reporting cleanup complete. Launch failure is never network-block evidence.
Timeout/missing cleanup latches `RuleLifetimeGuard` against removal. Never remove
the rule until all owned processes are confirmed dead. There is no deletion API;
the guard cannot prevent an unrelated administrator changing rules mid-run.

Current tests compile the real helper and test unrestricted TCP/UDP IPv4/IPv6
loopback echoes. Dedicated-account launch, effective SID filtering, LAN tests and
restricted descendants remain unexecuted until prerequisites are supplied.
Chromium is NOT launched: next test must keep the verified SID/Job launcher,
observe every identifiable descendant, use synthetic memory HTML, no debugger
TCP, and keep Chromium's sandbox. Helper results do not prove Chromium isolation.

Official contracts:
- [LocalUser firewall rule parameter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
- [CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)

## Diagnostic report version 2

The helper emits fixed `diag=stage,win32_code` records; managed failures/timeouts
use code 0 rather than stale last-error values. No messages, command lines or
credentials are exported. Kernel P/Invokes preserve last error. Job accounting
uses the typed JOBOBJECT_BASIC_ACCOUNTING_INFORMATION and its exact native size,
not a generic 128-byte buffer/hard-coded offset.

Process creation, PID, root token, Job membership, root exit and exit code,
verified child indices and completed attempt results remain independent of
`job_empty`/handle cleanup. A failed later child retains earlier completed
attempts. Parent timeout retains bounded partial stdout but cannot certify
cleanup. Remaining PIDs are unknown (`None`) if cleanup is unconfirmed; a
separate later process check does not retrospectively certify this execution.

The reviewed copy of the external Downloads runner is
`tools/experimental/jarvis_sid_lab_runner_review.py`. It does not overwrite the
original. Listener-count deltas never override classification: the fixed marker
does not authenticate an emitter SID. A new restricted run requires an operator
decision; diagnostics alone do not prove why the previous run was inconclusive.
