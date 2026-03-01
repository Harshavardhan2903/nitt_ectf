# Fortress-M0: Architectural Code Highlights

This document maps the **Fortress-M0** security features to the specific lines and files changed from the original insecure implementation.

---

## 1. Secrets Generation ($K_{root}$)
**Goal:** Replace the static "EXAMPLE" secret with a high-entropy 256-bit master key.

### [Insecure Implementation]
- **File:** `ectf26_design/src/gen_secrets.py`
- **Logic:** Returned a static JSON with `"some_secrets": "EXAMPLE"`.

### [Fortress-M0 Implementation]
- **File:** `ectf26_design/src/gen_secrets.py`
- **Change:** 
```python
# Added 256-bit entropy generation
root_secret = os.urandom(32).hex() 
secrets = {"groups": groups, "root_secret": root_secret}
```

---

## 2. Personalization & Hashing
**Goal:** Protect the technician's PIN using one-way cryptographic hashing and salts.

### [Insecure Implementation]
- **File:** `firmware/src/security.c` (Function: `check_pin`)
- **Logic:** Perform a direct `strcmp` between the user input and the clear-text `HSM_PIN`.

### [Fortress-M0 Implementation]
- **File:** `firmware/src/security.c` (Function: `check_pin`)
- **Change:**
```c
// Combined salt with PIN and hashed it
memcpy(salted_pin, HSM_PIN_SALT, 16);
memcpy(salted_pin + 16, pin, PIN_LENGTH);
hash(salted_pin, sizeof(salted_pin), computed_hash);
// Used constant-time comparison to prevent timing leaks
return CRYPTO_memcmp(computed_hash, HSM_PIN_HASH, HASH_SIZE) == 0;
```

---

## 3. Cryptographic Core
**Goal:** Move from obsolete/weak primitives (MD5, AES-Direct) to modern, authenticated primitives (SHA-256, AES-GCM).

### [Insecure Implementation]
- **File:** `firmware/src/simple_crypto.c`
- **Logic:** Used `wc_Md5Hash` and `wc_AesEncryptDirect` (no integrity check).

### [Fortress-M0 Implementation]
- **File:** `firmware/src/simple_crypto.c`
- **Change:**
```c
// Upgraded to SHA-256
int hash(...) { return wc_Sha256Hash(data, len, hash_out); }
// Upgraded to AES-256-GCM (Authenticated Encryption)
int aes_gcm_encrypt(...) {
    return wc_AesGcmEncrypt(&ctx, ciphertext, plaintext, len, iv, 12, tag, 16, aad, aad_len);
}
```

---

## 4. Secure File System
**Goal:** Protect Intellectual Property on the chip using per-device encryption keys.

### [Insecure Implementation]
- **File:** `firmware/src/filesystem.c` (Function: `write_file`)
- **Logic:** Immediately wrote `src` buffer to flash using `flash_simple_write`.

### [Fortress-M0 Implementation]
- **File:** `firmware/src/filesystem.c` (Function: `write_file` / `read_file`)
- **Change:**
```c
// Encryption before writing
aes_gcm_encrypt(src->contents, src->contents_len, K_dev, src->iv, aad, sizeof(aad), src->contents, src->gcm_tag);
// Decryption and Verify Tag after reading
aes_gcm_decrypt(dest->contents, dest->contents_len, K_dev, dest->iv, aad, sizeof(aad), dest->gcm_tag, dest->contents);
```

---

## 5. Secure Channel Protocol (SCP)
**Goal:** Prevent replay attacks and eavesdropping during inter-device transfers.

### [Insecure Implementation]
- **File:** `firmware/src/commands.c` (Function: `receive`)
- **Logic:** Sent `receive_request_t` in plaintext and waited for a plaintext `receive_response_t`.

### [Fortress-M0 Implementation]
- **File:** `firmware/src/commands.c` (Function: `receive` / `listen`)
- **Change:**
```c
// Implemented Challenge-Response
for (int i = 0; i < 12; i++) challenge[i] = (uint8_t)rand();
write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, challenge, 12);
// Verified Challenge in GCM AAD
aes_gcm_decrypt(transfer_buf + 28, sizeof(recv_resp), K_dep, iv, challenge, 12, tag, (uint8_t *)&recv_resp);
```

---

## 6. Code Cleanup & De-obfuscation
**Goal:** Eliminate "security by obscurity" and developer backdoors.

### [Insecure Implementation]
- **File:** `firmware/src/HSM.c`
- **Logic:** Contained heavily obfuscated code for `boot_flag`, which was actually the reference design's "flag."

### [Fortress-M0 Implementation]
- **File:** `firmware/src/HSM.c`
- **Change:** Deleted `boot_flag`, `deobfuscate`, and the associated global arrays. Cleaned up the main loop to only handle valid, secured commands.
