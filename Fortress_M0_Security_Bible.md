# Fortress-M0: High-Assurance Security Architecture

This document provides a comprehensive technical and theoretical analysis of the security transformation from the "Insecure Reference Design" to the production-ready **Fortress-M0**.

---

## 1. The Foundation: The Master Secret ($K_{root}$)

In any secure system, the strength of the entire architecture is limited by the strength of its first secret.

### The Problem
The reference design used a human-readable secret. If an attacker stole the source code or build logs, they could easily identify the secret and unlock every device in the field.

### The Solution: 256-bit Entropy
We now generate a **256-bit Master Secret** at build time using a cryptographically secure random number generator (`os.urandom`).

*   **Theory (The Scale of 256-bits):** A 256-bit key has $2^{256}$ possible combinations. This number is roughly $1.15 \times 10^{77}$. To put this in perspective:
    *   There are roughly $10^{80}$ atoms in the observable universe.
    *   If you had a trillion computers, each checking a trillion keys per second, it would still take trillions of years to guess the key.
*   **Result:** The "front door" to your ecosystem is now mathematically unhackable by brute force.

---

## 2. Identity & Access: Secured PINs

The PIN is how the system identifies the user (the Technician). Protecting it is critical to prevent unauthorized access.

### The Transformation
- **Insecure:** Stored as "123456" in flash memory.
- **Secure:** Stored as `SHA-256(Salt + PIN)`.

### Core Theory: Hashing & Salts
1.  **The One-Way Function (Hashing):** Think of **SHA-256** as a meat grinder. You can put a file in and get "hamburger meat" (the hash) out, but you can never reconstruct the file from the meat. The system only stores the "meat." When you type your PIN, the system grinds it and checks if the output matches what's on file.
2.  **The Salt (Diversification):** Even if two devices have the same PIN, we add a random 16-byte **Salt** to each. 
    *   *Analogy:* If two people both have the name "John," adding a unique birthdate (the salt) ensures their IDs are different. This prevents an attacker from using a "Rainbow Table" (a pre-computed list of common PIN hashes).
3.  **Constant-Time Comparison:** When checking the PIN, we use `CRYPTO_memcmp`. 
    *   *Theory:* Normal comparison stops as soon as it finds a wrong digit. An attacker with a high-speed clock can see *how long* the check took and figure out which digit was wrong. `CRYPTO_memcmp` always checks every single digit, regardless of whether it's right or wrong, leaking zero timing information.

---

## 3. Data at Rest: Secure Flash Storage

Intellectual Property (IP) files are stored in the device's flash memory. Encryption ensures that even if someone steals the physical chip, the data is useless.

### The "A-E-S" of Secure Storage
We use **AES-256-GCM** (Advanced Encryption Standard with Galois/Counter Mode).

*   **Theory (Confidentiality):** The file is scrambled using a 256-bit key. Without the key, the file looks like random static.
*   **Theory (Integrity & Authenticity):** The "GCM" part adds a **Tag**. This is a digital seal. If a single bit of the encrypted file is changed while it's sitting on the chip, the seal will fail when we try to read it.
*   **Theory (The IV):** We use an **Initialization Vector**. Even if you encrypt the *exact same file* twice, the output will look completely different because the IV changes every time. This prevents an attacker from seeing patterns in the data.

---

## 4. Hierarchy: Key Derivation (HKDF)

We never use the "Master Key" ($K_{root}$) directly for anything. We use it to "manufacture" specific keys for specific tasks.

### The Factory Analogy (HKDF)
We use the **Hash-based Key Derivation Function (HKDF)**.

*   **Device Key ($K_{dev}$):** Manufactured using $K_{root}$ + the **unique Hardware ID** of the CPU.
    *   *Security Benefit:* This "binds" the data to the physical device. If an attacker moves the flash memory chip from a secure device to a hacked device, the hacked device cannot generate $K_{dev}$ and therefore cannot read the files.
*   **Deployment Key ($K_{dep}$):** Manufactured using $K_{root}$ + a fixed "Deployment String." 
    *   *Security Benefit:* This allows two devices in the same company to talk to each other while keeping their internal storage keys private.

---

## 5. Transport: The Secure Channel Protocol (SCP)

Sending data over wires (UART) is dangerous because an attacker can "listen" or "inject" data.

### Stopping the "Tape Recorder" (Replay Attacks)
Imagine a "Listen" command. If an attacker records the "Success" signal from yesterday and plays it back today, the system might be fooled. 

**Fortress-M0 Solution:**
1.  **Challenge:** The Receiver sends a random 12-byte "Challenge" (a number used only once - a **Nonce**).
2.  **Authenticated Data:** The Sender encrypts the file and includes that *specific* Challenge in the "Authenticated Data" (AAD).
3.  **Verification:** The Receiver only accepts the packet if the GCM seal is valid **and** the Challenge inside the seal matches the one they just sent.

*   **Analogy:** It's like a spy mission. Instead of a fixed password, the guard says "What is 5 + 9?" and the spy says "14." Tomorrow, the guard says "What is 2 + 8?" Even if the attacker recorded "14" yesterday, it won't work today.

---

## 6. Zero Knowledge Summary
- **Master Secret**: Our massive universe-sized lock code.
- **Hashing**: Turning a PIN into a fingerprint that can't be reversed.
- **AES-GCM**: Scrambling data and putting a tamper-proof seal on it.
- **HKDF**: A key factory that makes unique keys for storage and transport.
- **SCP**: A handshake that changes every single time to stop replay attacks.
- **Perimeter Defense**: We removed all "shortcut" code and "debugging" flags that the original designers left behind.
