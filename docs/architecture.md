# PKCertChain Architecture (Simplified)

**Goal:** High-performance, memory-optimized blockchain for Linux nodes (server, desktop, edge).

---

## 1. Layers

**Kernel Layer (`KernelBlockInteractor`):**

* Handles: packet reception, streaming, event dispatch, PoW capability classification
* Hard real-time (deterministic)
* Zero-copy buffers to user-space
* Minimal logic - only orchestration, timers, validation

**User-Space Layer (`BlockchainInterface`):**

* Handles: blockchain logic, ledger, consensus, rewards, fork resolution
* Soft real-time
* Converts raw kernel buffers to structured blockchain blocks
* Applies PoW verification and signature checks

---

## 2. Packet Handling

* **Canonical Serialization:** All integers in **network byte order (big-endian)**
* **Zero-copy philosophy:** Kernel passes buffer pointers; user-space copies only if needed
* **Deterministic hashing:** Always hash **serialized buffers**, not native structs
* **Bit & byte layout:** Explicit, no compiler-dependent padding

---

## 3. Structures (Current Implementation)

**Certificate (`blockchain/certificate.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint256 pubSignKey;    // 32 bytes
    uint256 pubEncKey;     // 32 bytes
    uint8_t  id;           // 1 byte
    uint8_t  reserved[3];  // padding
} certificate;
```

**Block (`blockchain/block.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    certificate cert;
    uint256 CurrentCertHash;
    uint256 prevHash;
    uint512 SignedByVerifier;
    uint64_t height;
    uint64_t timestamp;
} block;
```

**MiniPoW Challenge (`Proofs/MiniPoW/miniPoWChallenge.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint256 challenge;    // 32 bytes
    uint8_t complexity;   // 1 byte
    uint64_t challenge_id;// 8 bytes
    uint8_t reserved[3];  // padding
} mini_pow_challenge_t;
```

**MiniPoW Solve (`Proofs/MiniPoW/miniPoWSolve.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint64_t nonce;       // 8 bytes
    uint8_t complexity;   // 1 byte
    uint64_t challenge_id;// 8 bytes
    uint8_t reserved[3];  // padding
} mini_pow_solve_t;
```

**MiniPoW Session (`Proofs/MiniPoW/miniPoWSession.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    mini_pow_challenge_t challenge;
    uint64_t issued_time_seconds;
    uint64_t received_time_seconds;
    uint32_t target_index;
} mini_pow_session_t;
```

---

## 4. Crypto & Key Management

**Signing (Ed25519):**
- `SignUtils` provides `GenerateSignKeys`, `sign_buffer_ed25519`, and verification helpers.

**Encryption (X25519 + AES-GCM at rest):**
- `EncUtils` provides `GenerateEncKeys` and AES-256-GCM helpers.
- Encrypted file format:
  - `[magic(4)][salt(16)][iv(12)][tag(16)][ciphertext]`
  - Key derivation: `SHA256(password || salt)`

**Wallet Directory:**
- `~/.pkcertchain/<network>/wallet` created with mode `0700`.
- Key files saved as encrypted blobs with mode `0600`.
- `LinuxUtils` provides `save_*` and `load_*` helpers.

---

## 5. PoW Flow & Queueing

**Decoupled flow:**
1. `verify_prev_block`
2. `give_mini_pow_challenge` (creates `mini_pow_session_t`)
3. `verify_mini_pow_solution`
4. `add_block_if_pow`

**Queueing:**
- `mini_pow_queue_t` stores active sessions + candidate blocks.
- `give_mini_pow_challenge_enqueue` adds sessions to the queue.
- `add_block_from_queue` pops by `challenge_id` and prunes stale sessions.

**Difficulty update:**
- Uses elapsed time between issue and solve.
- Faster than 5 min increases complexity; slower decreases.
- Clamped to `[1, 220]`.

---

## 6. Node Heterogeneity (Design)

1. **Server:** Full compute/storage, highest PoW
2. **Desktop:** Medium PoW
3. **Edge:** Low PoW

* Block target: 10 minutes (design goal)
* Block sync interval: 5 minutes (design goal)

---

## 7. Timing

* Kernel: `CLOCK_MONOTONIC_RAW` (hard RT)
* User-space: soft timers
* Use `uint64_t` timestamps for determinism

---

## 8. Security Principles

* Canonical serialization before hashing
* Signature verification and full PoW in user-space
* Zero-copy buffers with safe lifetime handling
* Replay protection for packets (to be implemented)

---

## 9. Event-Driven Kernel Design (Planned)

**Event types:**

```
EVENT_PACKET_RECEIVED
EVENT_PACKET_VERIFIED
EVENT_STREAM_SYNC
EVENT_CAPABILITY_CLASSIFIED
EVENT_TIMER_BLOCK_WINDOW
EVENT_PEER_CONNECTED
EVENT_PEER_DISCONNECTED
```

* Kernel orchestrates events/streaming
* User-space reacts via `BlockchainInterface`

---

**Key Idea:** Kernel orchestrates events and streaming, user-space handles ledger + consensus. All packet serialization is canonical, zero-copy, and deterministic for heterogeneous Linux nodes.
