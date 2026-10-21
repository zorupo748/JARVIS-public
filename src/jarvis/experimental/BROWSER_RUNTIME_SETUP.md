# Gated runtime setup — preparation is not validated Chromium integration

No accounts, firewall, ACL, system directories or scheduled tasks were modified.
Existing AppContainer experiments and earlier run artifacts are preserved.

## Win32 5: differentiated diagnosis

`diagnose_sid_access_review.py` uses hidden transient credentials for LogonUser,
verifies the standard SID, impersonates that token only for actual read/execute
opens, then reverts and closes handles. It does not launch a browser or load a
personal profile. Safe numeric records distinguish authentication failure from
file access denial, helper access and working-directory access. It does not test
desktop access: successful file opens alone do not prove CreateProcessWithLogonW
will succeed. No repeated equivalent browser launch is performed.

## Protected runtime: explicit approval gate

`browser_runtime_preparation.py` creates a NEW workspace staging directory from
19 required executables, DLLs, resources and a version manifest of the existing
browser. No cookies/profile/installer/elevation service is copied. Reparse paths,
unexpected files, modified bytes and manipulated manifest names are rejected.
Hashes bind an operator-approved local snapshot; they are not a vendor signature.
Workspace staging remains untrusted/writable and is NEVER an approved runtime.

The review-only script `tools/experimental/Install-BrowserRuntime-REVIEW.ps1`
requires an already elevated operator and the approved manifest SHA256. It does
not request elevation or execute itself. It creates only a NEW
`C:\Program Files\JARVISBrowserLab`, rejects an existing destination, protects its
DACL and owners against nonadministrative principals, and verifies copied hashes.
Only SYSTEM/Administrators receive full control; worker SID receives RX.
Executable owners are Administrators rather than the controller's personal SID,
so an unelevated controller/agent cannot use owner rights to replace their DACL.
It neither grants Everyone/Users access nor changes the Playwright original.
Profiles must remain separate. On failure preserve partial installation for
explicit review; no automated delete/overwrite/ACL expansion is provided.

Before a future launch, validate the installed tree's hashes, exact DACL, parent
chain and restricted-token RX **and inability to write/replace binaries**.
Do not turn successful staging or descriptor inspection into execution evidence.
If desktop/session/stdio or profile access still fails, retain the exact new
diagnostic and stop. Never grant broad personal-directory access automatically.

## Task Scheduler independent preparation

`browser_worker_task.py` prepares Password logon under the standard SID,
LeastPrivilege, no triggers, IgnoreNew and a 60-second acceptance limit. The
task descriptor gives SYSTEM/Administrators full control and controller read/run
only. An agent running arbitrary code under the controller can share run rights;
this is NOT authenticated agent isolation. Task XML never contains a password.
Initial registration may use operator credentials via the official Scheduler
API ONLY after approval; no credential registration/storage is implemented here.
Password logon permits noninteractive batch execution, subject to Windows logon
rights and policy. It does not require an already open interactive user session.

Read-only COM inspection returns absent/unreadable tasks as no authorization.
Prepared XML, DACL and protected worker path must match exactly. There is no
worker.exe installation, live scheduler dispatch or authenticated IPC yet;
`launch_scheduled_worker` deliberately denies rather than launching an arbitrary
task or silently using the controller identity. The lifecycle is a tested local
protocol skeleton, not an external client authenticator. It keeps duplicate
start, token/Job/IPC confirmation, stop and uncertain cleanup distinct.

Supervisor disappearance invalidates the local lease; this does NOT kill a
process. A real protected worker still needs a watchdog, an owned kill-on-close
Job, authenticated nonnetwork IPC, SID/Job inspection and confirmed profile
cleanup. Scheduler timeout/Stop alone cannot certify whole-family termination.
Uninstallation is a review specification only and is denied while cleanup is
uncertain; an operator must also confirm no running task instances.

Phases 2 and 4 remain gated on actual standard-SID Chromium execution. No real
Playwright pipe integration, gateway dispatch or Internet navigation is enabled.
Known loopback connectivity still prevents claiming general network isolation.

Official contracts:
- https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks
- https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-multipleinstances
