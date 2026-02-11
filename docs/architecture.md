# PKCertChain Architecture (Simplified)

**Goal:** High-performance, memory-optimized blockchain for heterogeneous Linux nodes (Servers, Desktop, Edge, MCUs).

---

## 1. Layers

**Kernel Layer (`KernelBlockInteractor`):**

* Handles: packet reception, streaming, event dispatch, PoW capability classification
* Hard real-time (deterministic)
* Zero-copy buffers to user-space
* Minimal logic — only orchestration, timers, validation

**User-Space Layer (`BlockchainInterface`):**

* Handles: full blockchain logic, ledger, consensus, rewards, fork resolution
* Soft real-time
* Converts raw kernel buffers to structured blockchain blocks
* Applies full PoW verification and signature checks

---

## 2. Packet Handling

* **Canonical Serialization:** All integers in **network byte order (big-endian)**
* **Zero-copy philosophy:** Kernel passes buffer pointers; user-space copies only if needed
* **Deterministic hashing:** Always hash **serialized buffer**, not native struct
* **Bit & byte layout:** Explicit, no compiler-dependent padding

---

## 3. Blockchain Structures

**Certificate:**

```c
typedef struct __attribute__((aligned(32))) {
    uint256 pubSignKey;
    uint256 pubEncKey;
    uint8_t id;
} certificate;
```

**Block:**

```c
typedef struct __attribute__((aligned(32))) {
    certificate cert;
    uint64_t timestamp;  // canonical monotonic timestamp
    uint8_t index;
} block;
```

**PoW Challenge:**

```c
typedef struct __attribute__((aligned(32))) {
    uint256* challenge;
    uint8_t* complexity;
} pow_t;
```

* All structs aligned for cache optimization (32-byte)
* PoW complexity tier scales with node capability

---

## 4. Node Heterogeneity

1. **Server:** Full compute/storage, highest PoW
2. **Desktop:** Medium PoW
3. **Edge:** Low PoW
4. **MCU:** Minimal PoW

* Block target: 10 minutes
* Block sync interval: 5 minutes

---

## 5. Timing

* Kernel: `CLOCK_MONOTONIC_RAW` (hard RT)
* User-space: soft timers (soft RT)
* Avoid floating timestamps; use `uint64_t` for determinism

---

## 6. Security Principles

* Immutable kernel buffers after verification
* Zero-copy for speed but safe (reference counting if needed)
* Signature verification and full PoW in user-space
* Replay protection for packets

---

## 7. Event-Driven Kernel Design

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

* Kernel acts purely as orchestrator
* User-space reacts to events via BlockchainInterface

---

## 8. Memory & Performance

* 32-byte cache alignment (optionally 16 bytes for MCUs)
* No floating point
* Manual serialization to avoid padding issues
* Fixed-size types only (`uint8_t, uint16_t, uint32_t, uint64_t`)
* Zero-copy for deterministic performance

---

**Key Idea:**
Kernel orchestrates **events and streaming**, user-space handles **ledger and consensus**. All packet serialization is canonical, zero-copy, and deterministic for heterogeneous nodes.

