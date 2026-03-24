# PKCertChain

PKCertChain is a Linux-focused blockchain prototype emphasizing deterministic serialization, lightweight PoW, and secure key management. The codebase is currently header-driven with minimal runtime scaffolding.

## Status
- Core data structures (block, certificate, uint256/uint512) implemented.
- MiniPoW challenge/solve/verify flow implemented.
- PoW session queue for outstanding challenges implemented.
- Ed25519 signing + verification helpers implemented.
- X25519 key generation and AES-256-GCM local key storage implemented.
- Wallet path: `~/.pkcertchain/<network>/wallet` with strict permissions.

## Key Components
- **Blockchain types:** `include/blockchain/`
- **PoW:** `include/Proofs/MiniPoW/`
- **PoW queue:** `include/Proofs/MiniPoW/miniPoWQueue.h`
- **Crypto helpers:** `include/util/SignUtils.h`, `include/util/EncUtils.h`
- **Wallet + OS helpers:** `include/util/WalletSetup.h`, `include/util/LinuxUtils.h`

## Notes
- `util/utilities.h` is an umbrella header for the split utils.
- `src/main.c` is a placeholder entrypoint.

## Next Steps
- Add storage + chain validation logic.
- Build CLI/GUI flows for password prompts and key management.
- Add tests for serialization, PoW, and crypto.

See `docs/CurrentImplementation.md` and `docs/architecture.md` for details.
