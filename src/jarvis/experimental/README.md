# Synthetic Chromium prototype

Experimental, opt-in and disconnected from main, the supervisor, request
authorization and production HTTP/DNS/SSRF/TLS. Only trusted synthetic HTML
fixtures are supported. Do not use this module for real websites or hostile HTML.

Install `requirements-browser-prototype.txt` in the project `.venv` only.
No browser is automatically installed. Tests first use Playwright's existing
browser, then an existing Windows Playwright cache, or the explicitly supplied
`JARVIS_SYNTHETIC_CHROMIUM` executable path. Missing browser/dependency produces
explicit integration skips; an existing executable that fails to launch fails
the test. Compatibility with an older cached Chromium is empirically tested,
not guaranteed across future Playwright revisions.

Run `.venv/Scripts/python.exe -m pytest tests/test_browser_synthetic_prototype.py -q`.
`SyntheticPrototypeRealChromiumTests` uses real browser processes and JavaScript;
`SyntheticPrototypeUnitTests` uses mocks or pure validation. The fixture's
DEMO-001 and DEMO-002 results are invented test data, never a real tracking service.

Each instance owns one fresh temporary context. HTML is loaded in memory with
`set_content`, not file/public navigation. Operations locate a unique DOM
element, read text, fill, click, wait for exact text and extract named fields.
Missing/ambiguous elements and timeouts are explicit errors without raw browser
messages. A failed load closes the context; extraction does not return a partial
result. Observations identify the fixture and `synthetic_dom` provenance; this
label is not an authenticity credential. Values are excluded from repr but
remain accessible in memory; there is no serializer, trace, screenshot or log.

HTTP requests are abort-only and WebSockets close without connecting upstream.
Service Workers, accepted downloads and permissions are disabled. Extra pages
close immediately. An explicit dead-end proxy and background/QUIC switches add
defense in depth. No caller can supply cookies, storage state, headers, URLs,
launch flags or a personal profile through this interface.

NONE of these controls proves network isolation. Chromium background traffic,
protocol-handler behavior and the OS have no independently tested egress barrier.
No production containment, protection against browser exploits, domain TLS
evidence, physical traffic budget or Internet readiness is claimed. The module
also does not securely erase memory or promise deletion of every browser temp
artifact. Public APIs have local bounds/timeouts, not a total hard CPU/RAM budget.

Future work must place the entire browser process tree behind proven network
isolation and an authenticated IPC boundary BEFORE admitting real web content.
The fixed small DOM interface can then live inside that worker. Adding request
authorization and an HTTP response adapter is separate work; no pass-through
route, network callback, permission bypass or custom resolver is provided here.
