These certificates and the server private key are PUBLIC TEST FIXTURES ONLY.
Never use this key or trust this CA in production or install it in the OS store.

The CA and normal certificates are valid from 2020-01-01 to 2050-01-01. The
expired certificate ended on 2021-01-01. `wrong-host.pem` names `other.test`;
`untrusted.pem` is self-signed. All leaf certificates use `server-key.pem`.
The CA private key was discarded. PEM fixtures were generated locally using
the existing cryptography installation; running the tests requires only the
standard library and does not regenerate certificates or access Internet.

The integration suite uses real TCP sockets, SSLContext, SSLSocket, handshake,
certificate/hostname verification, SNI and HTTP bytes. Test-only patches supply
synthetic DNS, a CA-only trust context, and translate logical 8.8.8.8:443 to the
listener's 127.0.0.1 ephemeral port. Peer translation first checks the actual
OS peer against that listener. Production SSRF/egress policy and broker peer
checks remain unchanged and still evaluate the logical admitted destination.
These tests do not demonstrate routing to a public IP or real DNS resolution.
