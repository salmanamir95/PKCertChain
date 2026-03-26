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
    Tier_t tier;
    uint8_t reserved[3];
    MiniPowResult miniPowResult;
    tier_pow_solve_t tierPoWResult;
} block;
```

**MiniPowResult (`Proofs/MiniPoW/miniPoWResult.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint32_t challengeid;
    uint32_t sessionid;
    Tier_t tier;
    bool isValid;
    uint8_t reserved[2];
} MiniPowResult;
```

**MiniPoW Challenge (`Proofs/MiniPoW/miniPoWChallenge.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint256 challenge;
    uint8_t complexity;
    uint64_t challenge_id;
    uint8_t reserved[3];
} mini_pow_challenge_t;
```

**MiniPoW Solve (`Proofs/MiniPoW/miniPoWSolve.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    uint64_t nonce;
    uint8_t complexity;
    uint64_t challenge_id;
    uint8_t reserved[3];
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

**TierPoW Session (`Proofs/TierPoW/tierPoWSession.h`):**

```c
typedef struct __attribute__((aligned(4))) {
    tier_pow_challenge_t challenge;
    uint64_t issued_time_seconds;
    uint64_t received_time_seconds;
    uint32_t target_index;
} tier_pow_session_t;
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
- Chain snapshot stored at `~/.pkcertchain/<network>/blockchainState`.

---

## 5. PoW Flow & Queueing

**Decoupled flow:**
1. Verify previous block
2. MiniPoW classification
3. Tier assignment (adaptive)
4. TierPoW mining
5. Add block (TierPoW only)

**Queueing:**
- MiniPoW and TierPoW each have independent session+queue modules.
- TierPoW queue is the only path that adds blocks.

**MiniPoW classification kernel (planned):**
- Matrix multiplication A(1000x1000) x B(1000x1000)
- Rank assignment based on elapsed time vs moving average

**Difficulty update:**
- 10-minute target (600s)
- Faster than target increases complexity; slower decreases
- Clamped to `[1, 220]`

---

## 6. Event-Driven, Multi-threaded Target (Planned)

- Event loop + MPSC queues
- Zero-copy buffer passing with reference counting
- Dedicated chain-writer thread
- PoW workers feed events to the chain thread

---

## 7. Security Principles

* Canonical serialization before hashing
* Signature verification and full PoW in user-space
* Zero-copy buffers with safe lifetime handling
* Replay protection for packets (to be implemented)

---

## 8. Event-Driven Kernel Design (Planned)

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
