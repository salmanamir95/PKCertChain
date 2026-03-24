# Current Implementation Status

## Codebase Overview

### Top-Level Layout
- `include/`: Public headers for blockchain types, PoW, crypto utilities, queueing, and OS helpers.
- `src/`: Minimal entrypoint (`main.c`) currently prints a hello message.
- `docs/`: Architecture and implementation status.
- `tests/`: Empty (no tests yet).

### Platform Target
- Linux-only build guard in `pkcertchain_config.h`.

---

## Implemented Features

### 1. Build System
- **CMake**: Configured for C11 (`project(pkcertchain C)`).
- **Dependencies**: OpenSSL (SHA256, EVP for Ed25519/X25519 and AES-GCM).
- **Optimization**: `-O3 -march=native`.

### 2. Core Data Structures
- **`uint256` (`datatype/uint256_t.h`)**
  - 256-bit little-endian word layout.
  - Serialization/deserialization to big-endian.
- **`uint512` (`datatype/uint512.h`)**
  - 512-bit type, serialization/deserialization.
- **`certificate` (`blockchain/certificate.h`)**
  - Public signing key, public encryption key, ID.
  - Hash + sign helpers.
- **`block` (`blockchain/block.h`)**
  - Certificate, current cert hash, prev hash, verifier signature, height, timestamp.
  - Full serialization/deserialization (big-endian fields).
- **`PKCertChain` (`blockchain/pkcertchain.h`)**
  - Fixed-size block array, `index`, `NetworkName`, `complexity`, and `next_challenge_id`.
  - Genesis block builds a self-signed certificate.

### 3. MiniPoW
- **Challenge (`Proofs/MiniPoW/miniPoWChallenge.h`)**
  - Deterministic challenge hash from serialized block fields.
  - `challenge_id` is now `uint64_t`.
- **Solve (`Proofs/MiniPoW/miniPoWSolve.h`)**
  - Brute-force nonce search.
  - Complexity check via leading-zero count (`clz256`).
  - `challenge_id` is now `uint64_t`.
- **Verify (`Proofs/MiniPoW/miniPoWVerify.h`)**
  - `isValidChallenge` verifies nonce against challenge hash + complexity.
- **Session (`Proofs/MiniPoW/miniPoWSession.h`)**
  - Tracks issued/received timestamps and `target_index`.
- **Queue (`Proofs/MiniPoW/miniPoWQueue.h`)**
  - Fixed-size array queue for active PoW sessions + candidate blocks.
  - `find/take` by `challenge_id` and prune by `target_index`.

### 4. Cryptography Utilities
- **SignUtils (`util/SignUtils.h`)**
  - `hash256_buffer` (SHA256 wrapper).
  - `clz256` for difficulty checks.
  - Ed25519 sign + verify (bool and status forms).
  - `GenerateSignKeys` (Ed25519 keypair generation).
- **EncUtils (`util/EncUtils.h`)**
  - `GenerateEncKeys` (X25519 keypair generation).
  - AES-256-GCM encryption/decryption helpers:
    - `LocalSaveEncrypt` / `LocalSaveDecrypt`.
    - Format: `[magic(4)][salt(16)][iv(12)][tag(16)][ciphertext]`.
    - Key derivation: `SHA256(password || salt)`.

### 5. Wallet & OS Helpers
- **WalletSetup (`util/WalletSetup.h`)**
  - Creates `~/.pkcertchain/wallet` with mode `0700`.
  - Returns `OP_NEEDS_PRIVILEGE` if permissions block creation.
- **LinuxUtils (`util/LinuxUtils.h`)**
  - Save encrypted keypairs with `0600` permissions:
    - `save_sign_keys`, `save_enc_keys`.
  - Load-or-generate keypairs:
    - `load_sign_keys`, `load_enc_keys`.
  - Uses AES-GCM encryption helpers and a user-provided password.

### 6. Chain Flow & Difficulty Update
- **Decoupled flow:**
  - `verify_prev_block` -> `give_mini_pow_challenge` -> `verify_mini_pow_solution` -> `add_block_if_pow`.
- **Queue helpers:**
  - `give_mini_pow_challenge_enqueue` and `add_block_from_queue`.
- **Difficulty update:**
  - Uses elapsed time between challenge issue and solve.
  - Faster than 5 min increases complexity; slower decreases.
  - Clamped to `[1, 220]`.

### 7. Status & Error Handling
- **`OpStatus_t` (`datatype/OpStatus.h`)**
  - Standard error codes (null pointer, buffer too small, invalid input, success).
  - Added: `OP_NEEDS_PRIVILEGE`, `OP_SIGN_VERIFIED_TRUE/FALSE`, `OP_INVALID_STATE`.

---

## Remaining / To Do

### 1. Blockchain Core
- Persistent chain storage + reorg logic.
- Full chain validation beyond prev-block checks.
- Mempool + block assembly logic.
- Networking / P2P transport.

### 2. Wallet UX & Integration
- GUI flow to collect encryption password and call save/load helpers.
- Key rotation and migration support.

### 3. Testing
- Unit tests for serialization, PoW, signing, encryption.
- Integration tests for block creation + verification.

### 4. Documentation
- Expand architecture for queueing + difficulty tuning.

---

## Notes
- `util/utilities.h` now acts as an umbrella header for the split utils.
- `src/main.c` is a placeholder and does not exercise the core logic.
