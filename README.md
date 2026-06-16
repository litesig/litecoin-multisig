# litecoin-multisig

Litecoin multisig crypto core extracted from [LiteSig](https://litesig.com). Seven F# modules compiled to JavaScript via [Fable](https://fable.io), covering the full stack from BIP39 seed phrases to signed-and-broadcast PSBTs.

**No server. No custody. No single point of failure.**

## What's here

| Module | What it does |
|--------|-------------|
| `Types.fs` | `Network`, `ScriptType`, `NetworkParams` — Litecoin mainnet/testnet constants |
| `Crypto.fs` | SHA-256, RIPEMD-160, Hash160, SHA-256d, secp256k1 signature verification |
| `Bip32.fs` | BIP39 mnemonic generation/validation, BIP32 HD key derivation, BIP48 multisig paths (Ltub/ttub SLIP-132 version bytes) |
| `Script.fs` | BIP67 deterministic pubkey sorting, m-of-n multisig script assembly |
| `Address.fs` | P2SH, P2WSH, P2SH-P2WSH, P2PKH, P2WPKH address derivation with correct Litecoin prefixes |
| `Psbt.fs` | PSBT (BIP-174) creation, signing, combining, validation, finalization, and broadcast hex extraction |
| `KeyStore.fs` | AES-256-GCM + PBKDF2-SHA256 local key storage, browser `localStorage` + Node in-memory shim |

## Standards implemented

- **BIP-39** — mnemonic word lists and seed derivation
- **BIP-32** — hierarchical deterministic wallets
- **BIP-48** — multisig HD wallet structure (`m/48'/coin'/account'/script'`)
- **BIP-67** — deterministic pubkey ordering (required for deterministic multisig addresses)
- **BIP-141** — SegWit (P2WSH, P2SH-P2WSH)
- **BIP-174** — PSBT (Partially Signed Bitcoin Transaction)
- **SLIP-132** — Litecoin-specific extended key version bytes (`Ltub`/`Ltpv`, `ttub`/`ttpv`)

## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8) — for Fable
- Node.js 18+

## Running the tests

```sh
npm install
npm test
```

This compiles the F# to `test/build/Main.js` via Fable and runs 20+ test cases with Mocha, covering:

- SHA-256/RIPEMD-160/Hash160 against NIST vectors
- BIP39 seed derivation against official test vectors
- BIP32 extended key fingerprints and SLIP-132 version bytes
- BIP48 derivation path construction
- BIP67 pubkey sort ordering
- 2-of-3 and 3-of-5 multisig script assembly
- P2SH, P2WSH, P2SH-P2WSH address derivation cross-checked against bitcoinjs-lib
- Litecoin address prefixes (`ltc1q`, `tltc1q`, `M…`, `L…`)
- Full PSBT round-trip: create → sign (independent cosigners) → combine → validate → finalize → extract
- `signWithAccount` key-scan across address indexes
- AES-256-GCM KeyStore encrypt/decrypt/forget

## Used by

[LiteSig](https://litesig.com) — browser-based Litecoin multisig wallet. These modules run in the browser, compiled by Fable. All key material stays client-side; the server only sees AES-256-GCM encrypted blobs.

## License

MIT
