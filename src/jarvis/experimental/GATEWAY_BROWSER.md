# Opt-in Chromium gateway laboratory

`GatewayLaboratoryBrowser` is experimental and disabled unless trusted bootstrap
passes `enabled=True`. It is not registered in main, tools, skills or production
browser routing. Its only URL is the exact HTTP-transport encoding of one
pre-registered `https://browser.test:443` request; native request headers, cookies
and body are never forwarded to JARVIS. Other resources are aborted.

The trusted bootstrap retains the authority and session handles. The bridge
dispatches through the existing gateway. Tests alone substitute synthetic DNS,
CA trust and destination translation, reusing the existing loopback TLS lab.
TCP, TLS, HTTP and Chromium DOM execution remain real. No new dependencies or
public requests are required.

Delivery preserves HTTP status (including 403/404), decoded body and security
headers. Framing headers are removed; redirects, repeated headers, cookie/auth,
download and refresh responses are rejected rather than silently transformed.
DOM observations carry fixture ID, HTTP status and a synthetic provenance label.
These labels are not cryptographic evidence, functional success or real tracking.

Only the first matching main-document request can dispatch; reloads, iframes,
popups and secondary requests cannot obtain another dispatch through this bridge.
DOM operations reject a changed URL or an uncertain/failed delivery. This checks
document location, not cryptographic document identity: script may mutate the
DOM at the same URL, and observed text remains synthetic DOM evidence.

An exception/cancellation after `fulfill` begins is `delivery_uncertain`, not
proof that no bytes reached Chromium. Abort is best-effort and cannot withdraw
an accepted response. Extraction is disabled after such a failure; the delivery
commitment stays consumed, including when abort itself fails.

`authorize_delivery` rechecks session/permission expiry and revocation after
HTTP settlement and immediately before fulfillment. This linearizes a delivery
commitment; it does not atomically cancel Playwright IPC or withdraw previously
delivered DOM content after a later revocation. Such guarantees require a future
trusted delivery protocol. Quota remains consumed on delivery failure.

Service Workers, downloads and extra pages are blocked using the existing
synthetic browser lifecycle. WebSockets are closed without server connection.
Playwright routing and a dead-end proxy do **not** prove OS network isolation.
Chromium background traffic/subprocesses remain outside that guarantee. Only
trusted synthetic HTML is allowed; there is no claim of safe Internet browsing.

Run `python -m pytest tests/test_browser_gateway_browser.py -q` in the project
venv. Missing Chromium is explicitly skipped; launch failures are failures.
Start Playwright before installing the lab socket patches: Windows asyncio
uses a local socket pair during initialization, independent of broker traffic.
