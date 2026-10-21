# AppContainer auxiliary experiment (not Chromium isolation)

`appcontainer_probe.py` creates one UUID-named profile with the official
CreateAppContainerProfile API, obtains its SID/folder and copies only the trusted
test executable there. CreateProcessW uses STARTUPINFOEX and
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES with ZERO capabilities. No network
capability or loopback exemption is granted. The child starts suspended, is
assigned to a kill-on-close Job Object, and then resumed.

The C# fixture reads its actual process token using TokenIsAppContainer,
TokenAppContainerSid and TokenCapabilities. This is a trusted auxiliary report,
not an authentication mechanism for arbitrary hostile executables. This API is
test infrastructure, not exposed to the agent or connected to production.

Tests compile the helper using the already installed .NET Framework C# compiler
without downloading dependencies. Generated executables live in a unique
temporary folder beneath the ignored project `.cache` and are removed by tests.
The only targets are literal 127.0.0.1 and ::1 with ephemeral TCP/UDP listeners.
The SAME helper outside AppContainer must successfully send markers that every
listener actually receives, both before and after the restricted run.

Interpretation is deliberately conservative:
- Failure before starting the child: `launch_failed`, never network blocking.
- Started child with wrong token facts: `identity_failed`.
- Successful TCP connect: `network_not_blocked`.
- Verified SID/zero capabilities and access denial 10013 for EVERY endpoint:
  `network_blocked` (limited to the endpoints tested).
- Timeout, accepted UDP send, missing report or failed helper: `inconclusive`.
  UDP send acceptance does not establish packet receipt. Listener silence has
  only the significance of the finite experimental observation window.

On this Windows 11 Home host the helper starts, reports the expected SID and
zero capabilities, and exits normally. Both TCP attempts time out; both UDP
sends are accepted, but none of the four listeners receives restricted traffic.
Positive controls work before/after. Consequently the strict result remains
INCONCLUSIVE for explicit OS network denial; do not represent it as a verified
general no-network barrier. No firewall/exemption changes are used to make it pass.

All paths used for cleanup originate from the profile successfully CREATED by
this invocation. Existing/colliding profiles are never deleted. Only the two
known copied/report files are unlinked; DeleteAppContainerProfile removes the
owned profile. Profile storage disappearance is checked. Process termination,
handle closure and profile/file deletion failures are exposed separately as
`cleanup_complete=False` plus local resource labels in `remaining_resources`.
There is no recursive filesystem removal or broad profile cleanup command.

Run `.venv/Scripts/python.exe -m pytest tests/test_browser_appcontainer_probe.py -q -s`.
Real tests cover launch, token identity, controlled network observations,
CreateProcess failure, helper failure and timeout/termination. Pure tests cover
classification and malformed reports. Missing Windows/compiler causes explicit
skips, not a claim that networking was blocked.

Not covered: DNS/DoH, LAN/public egress, Chromium/Playwright, nested process
identities, hostile token changes, IPC, WFP, persistent policies or exhaustive
OS containment. No administrator request or system configuration change is made.
