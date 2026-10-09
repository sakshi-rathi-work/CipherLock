"""CipherLock Phase 5 CLI Demonstration Script.

Demonstrates RSA-OAEP Key Wrapping and RSA-PSS Digital Signatures:
1. RSA-3072 key generation for Siddharth (sender) and Vidhi (recipient).
2. AES-256 session key wrapping with RSA-OAEP (384 bytes wrapped length).
3. RSA-OAEP randomized padding verification (different outputs, same plaintext key).
4. Recipient unwrapping success and non-recipient unwrapping failure (fail closed).
5. RSA-PSS digital signing with SHA-256 and 32-byte salt.
6. Signature verification success and bit-flip tampering rejection.
7. RSA-PSS randomized signature verification (different signature bytes, both valid).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure workspace root is in Python path for scripts invocation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto.aes import generate_session_key
from crypto.rsa import (
    UnwrapError,
    generate_rsa_keypair,
    unwrap_session_key,
    wrap_session_key,
)
from crypto.signatures import sha256_hex, sign_data, verify_signature


def run_demo():
    print("================================================================")
    print("   CIPHERLOCK PHASE 5 — DEMO: RSA-OAEP WRAPPING & RSA-PSS SIGS   ")
    print("================================================================\n")

    # Step 1: In-memory key generation for Siddharth (sender) and Vidhi (recipient)
    print("[1] Generating RSA-3072 key pairs for Siddharth and Vidhi...")
    siddharth_priv, siddharth_pub = generate_rsa_keypair(bits=3072)
    vidhi_priv, vidhi_pub = generate_rsa_keypair(bits=3072)
    attacker_priv, attacker_pub = generate_rsa_keypair(bits=3072)
    print("    [+] Siddharth RSA-3072 KeyPair generated.")
    print("    [+] Vidhi RSA-3072 KeyPair generated.")
    print("    [+] Attacker RSA-3072 KeyPair generated.\n")

    # Step 2: Session Key Generation & RSA-OAEP Wrapping
    print("[2] AES Session Key Generation & RSA-OAEP Wrapping")
    session_key = generate_session_key()
    print(f"    Raw AES-256 Session Key (32 bytes hex): {session_key.hex()}")

    wrapped_key_1 = wrap_session_key(vidhi_pub, session_key)
    print(f"    Wrapped Key Length: {len(wrapped_key_1)} bytes (Expected: 384 bytes for RSA-3072)")

    # OAEP Randomized Property
    wrapped_key_2 = wrap_session_key(vidhi_pub, session_key)
    oaep_randomized = wrapped_key_1 != wrapped_key_2
    print(f"    OAEP Probabilistic Encryption Check: {'PASSED' if oaep_randomized else 'FAILED'}")
    print(f"    -> Two wrap operations produced different ciphertexts? {oaep_randomized}\n")

    # Step 3: Key Unwrapping & Access Control Checks
    print("[3] Key Unwrapping & Access Control Verification")

    # 3a. Vidhi (intended recipient) unwraps
    unwrapped_by_vidhi = unwrap_session_key(vidhi_priv, wrapped_key_1)
    vidhi_success = unwrapped_by_vidhi == session_key
    print(f"    [+] Vidhi (intended recipient) unwrap: {'SUCCESS' if vidhi_success else 'FAILED'}")
    print(f"        Matching original key: {vidhi_success}")

    # 3b. Siddharth tries to unwrap key intended for Vidhi
    try:
        unwrap_session_key(siddharth_priv, wrapped_key_1)
        siddharth_fail = False
    except UnwrapError:
        siddharth_fail = True
    print(f"    [+] Siddharth (non-recipient) unwrap attempt: {'REJECTED (Correct)' if siddharth_fail else 'SECURITY FAILURE'}")

    # 3c. Attacker tries to unwrap key intended for Vidhi
    try:
        unwrap_session_key(attacker_priv, wrapped_key_1)
        attacker_fail = False
    except UnwrapError:
        attacker_fail = True
    print(f"    [+] Attacker unwrap attempt: {'REJECTED (Correct)' if attacker_fail else 'SECURITY FAILURE'}\n")

    # Step 4: RSA-PSS Digital Signatures
    print("[4] RSA-PSS Digital Signatures & Integrity Verification")
    message = b"Canonical Package Header Payload: version=1, sender=Siddharth, receiver=Vidhi"
    print(f"    Payload: {message.decode('utf-8')}")
    print(f"    SHA-256 Digest: {sha256_hex(message)}")

    sig_1 = sign_data(siddharth_priv, message)
    print(f"    Signature Length: {len(sig_1)} bytes (Expected: 384 bytes)")

    # Verification by Vidhi using Siddharth's public key
    valid_sig = verify_signature(siddharth_pub, message, sig_1)
    print(f"    [+] Signature verification with Siddharth's public key: {'VALID' if valid_sig else 'INVALID'}")

    # 4b. Verification with wrong public key (Attacker's pub key)
    wrong_pub_verify = verify_signature(attacker_pub, message, sig_1)
    print(f"    [+] Signature verification with Attacker's public key: {'REJECTED' if not wrong_pub_verify else 'SECURITY FAILURE'}")

    # 4c. Bit-flip tampering detection
    tampered_message = b"Canonical Package Header Payload: version=1, sender=Siddharth, receiver=Attacker"
    tampered_verify = verify_signature(siddharth_pub, tampered_message, sig_1)
    print(f"    [+] Verification of tampered message: {'REJECTED (Tamper Detected)' if not tampered_verify else 'SECURITY FAILURE'}")

    # 4d. Corrupted signature payload
    corrupted_sig = bytearray(sig_1)
    corrupted_sig[20] ^= 0xFF
    corrupted_verify = verify_signature(siddharth_pub, message, bytes(corrupted_sig))
    print(f"    [+] Verification of corrupted signature bytes: {'REJECTED (Tamper Detected)' if not corrupted_verify else 'SECURITY FAILURE'}\n")

    # Step 5: PSS Signature Randomization
    print("[5] RSA-PSS Salted Signature Randomization Check")
    sig_2 = sign_data(siddharth_priv, message)
    pss_randomized = sig_1 != sig_2
    both_valid = verify_signature(siddharth_pub, message, sig_1) and verify_signature(siddharth_pub, message, sig_2)
    print(f"    -> Two sign operations produced different signature bytes? {pss_randomized}")
    print(f"    -> Both signatures verify successfully with public key? {both_valid}")
    print(f"    RSA-PSS Salt Randomization Check: {'PASSED' if (pss_randomized and both_valid) else 'FAILED'}\n")

    # Summary Check
    all_passed = (
        vidhi_success
        and siddharth_fail
        and attacker_fail
        and valid_sig
        and not wrong_pub_verify
        and not tampered_verify
        and not corrupted_verify
        and oaep_randomized
        and pss_randomized
        and both_valid
    )

    print("================================================================")
    print(f"   PHASE 5 VERIFICATION SUMMARY: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}   ")
    print("================================================================")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    run_demo()
