# Handoff: Nostr Signing-Agent API for KeyMaster

## Summary

WhiteNoise has been fully wired to delegate all cryptographic
operations to an external signing agent via a Unix socket. The API is
proven end-to-end: a reference daemon (`sa-daemon`) and client library
(`sa-client`) exist, an integration test covers all 11 RPC methods,
and the full app (login, chat, MLS group operations) works with the
daemon as the sole key holder. No private key material enters the
WhiteNoise process.

This document describes the proven API so that KeyMaster can implement
the same 11 methods in its `NostrServiceHandler`. Once KeyMaster's
handler is operational, WhiteNoise connects to it via the same
`NOSTR_SA_SOCK` interface — no app-side changes needed.

## What was built (Mission 6)

| Component | Repo | Purpose |
|-----------|------|---------|
| `wn-kv-core` | `wn-kv-test/crates/core` | Key manager (BIP-39 → vault-backed signers) |
| `sa-rpc-types` | `wn-kv-test/crates/rpc-types` | Shared JSON-RPC types and framing |
| `sa-daemon` | `wn-kv-test/crates/sa-daemon` | Reference daemon binary |
| `sa-client` | `wn-kv-test/crates/sa-client` | Client library with trait impls |
| Integration test | `sa-client/tests/daemon_integration.rs` | Covers all 11 methods |
| WhiteNoise wiring | `whitenoise-linux` | `backend.rs`, `panes.rs`, `main.rs` |

### Architecture

```
┌──────────────────┐     Unix socket      ┌─────────────────┐
│  WhiteNoise      │ ──── JSON-RPC ─────▶ │  sa-daemon      │
│  (no key material│     (NOSTR_SA_SOCK)   │  (holds mnemonic│
│   in process)    │ ◀──────────────────── │   + vault)      │
└──────────────────┘                       └─────────────────┘
         │                                          │
    sa-client types:                          wn-kv-core:
    SaAccountClient                           KmLight
    SaMlsSigner                               VaultAccountSigner
    SaHpkeBackend                             MlsVaultSigner
```

**Future (KeyMaster replaces sa-daemon):**

```
┌──────────────────┐     Unix socket      ┌─────────────────┐     NIP-44 relay     ┌──────────┐
│  WhiteNoise      │ ──── JSON-RPC ─────▶ │  km-nostr-sa    │ ──── encrypted ────▶ │ KeyMaster│
│                  │     (NOSTR_SA_SOCK)   │  (local avatar) │     kind 27235       │ (vault)  │
└──────────────────┘                       └─────────────────┘                      └──────────┘
```

The sa-client library remains unchanged. Only the process behind the
socket changes — from `sa-daemon` (local vault) to `km-nostr-sa`
(avatar relaying to KeyMaster).

## Wire protocol

- **Transport**: Unix domain socket
- **Framing**: 4-byte big-endian length prefix + JSON payload
- **Encoding**: JSON-RPC 2.0
- **Byte arrays**: hex-encoded strings (Nostr convention)
- **Max frame**: 1 MiB

```
┌────────────┬───────────────────────────┐
│ 4 bytes BE │ JSON-RPC request/response │
│ (length)   │ (UTF-8)                   │
└────────────┴───────────────────────────┘
```

### Startup protocol

The daemon (or avatar):
1. Binds a Unix socket at a path of its choosing
2. Prints `NOSTR_SA_SOCK=<path>; export NOSTR_SA_SOCK;` on stdout
3. Enters the accept loop

WhiteNoise reads `NOSTR_SA_SOCK` from the environment and connects.

## API methods (11 total)

All byte array fields are **hex-encoded strings** on the wire.

### 1. `get_public_keys`

List all Nostr public keys managed by this signer.

```json
→ { "jsonrpc": "2.0", "id": 1, "method": "get_public_keys" }
← { "jsonrpc": "2.0", "id": 1, "result": {
      "nostr_pubkeys": ["<hex-32>", ...]
   }}
```

### 2. `get_mls_pubkey`

Return the Ed25519 MLS signing pubkey for a Nostr identity.

```json
→ { "method": "get_mls_pubkey", "params": {
      "nostr_pubkey": "<hex-32>",
      "device_id": null,
      "ciphersuite": 1
   }}
← { "result": { "mls_pubkey": "<hex-32>" }}
```

| Field | Type | Description |
|-------|------|-------------|
| `nostr_pubkey` | `string` | Hex 32-byte Nostr x-only pubkey |
| `device_id` | `string?` | Optional device discriminator (null = default) |
| `ciphersuite` | `u16` | `0x0001` = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 |
| `mls_pubkey` | `string` | Hex 32-byte Ed25519 public key |

**Side effect**: the daemon caches the MLS signer internally. All
subsequent `mls_sign`, `mls_hpke_*` calls reference the MLS pubkey,
not the Nostr pubkey.

### 3. `sign_event`

Schnorr-sign a Nostr event (secp256k1).

```json
→ { "method": "sign_event", "params": {
      "nostr_pubkey": "<hex-32>",
      "unsigned_event_json": "<json-string>"
   }}
← { "result": { "signed_event_json": "<json-string>" }}
```

### 4. `sign_account_identity_proof`

Schnorr-sign the binding between a Nostr identity and an MLS leaf
node. Proves the Nostr key holder controls the MLS signing key.

```json
→ { "method": "sign_account_identity_proof", "params": {
      "account_identity": "<hex-32>",
      "mls_signature_public_key": "<hex-32>",
      "ciphersuite": 1,
      "signature_scheme": 2055
   }}
← { "result": { "signature": "<hex-64>" }}
```

The signed payload is a deterministic hash of the four fields. See
`cgka-engine/src/account_identity_proof.rs` for the hash computation.

### 5. `nip44_encrypt`

NIP-44 encrypt a plaintext string for a peer.

```json
→ { "method": "nip44_encrypt", "params": {
      "nostr_pubkey": "<hex-32>",
      "peer_pubkey": "<hex-32>",
      "plaintext": "<utf8-string>"
   }}
← { "result": { "ciphertext": "<nip44-payload>" }}
```

### 6. `nip44_decrypt`

NIP-44 decrypt a ciphertext from a peer.

```json
→ { "method": "nip44_decrypt", "params": {
      "nostr_pubkey": "<hex-32>",
      "peer_pubkey": "<hex-32>",
      "ciphertext": "<nip44-payload>"
   }}
← { "result": { "plaintext": "<utf8-string>" }}
```

### 7. `mls_sign`

Ed25519-sign arbitrary data with the MLS signing key.

```json
→ { "method": "mls_sign", "params": {
      "mls_pubkey": "<hex-32>",
      "data": "<hex>"
   }}
← { "result": { "signature": "<hex-64>" }}
```

High-frequency: called for every sent MLS message (commits,
proposals, application messages).

### 8. `mls_hpke_pubkey_at`

Return the X25519 public key at a given derivation position.

```json
→ { "method": "mls_hpke_pubkey_at", "params": {
      "mls_pubkey": "<hex-32>",
      "key_type": "init",
      "index": 0
   }}
← { "result": { "hpke_pubkey": "<hex-32>" }}
```

| Field | Type | Values |
|-------|------|--------|
| `key_type` | `string` | `"init"` (KeyPackage init keys) or `"enc"` (tree encryption keys) |
| `index` | `u32` | Monotonic derivation counter (0, 1, 2, ...) |

### 9. `mls_hpke_dh`

X25519 Diffie-Hellman using a previously issued HPKE key.

```json
→ { "method": "mls_hpke_dh", "params": {
      "hpke_pubkey": "<hex-32>",
      "peer_public": "<hex>"
   }}
← { "result": { "dh_result": "<hex-32>" }}
```

The handler must resolve which private key corresponds to
`hpke_pubkey`. The reference daemon searches all cached MLS signers
across both key types (`init`, `enc`) and indices 0..255.

### 10. `mls_next_hpke_init_key`

Advance the init key counter and return the next X25519 pubkey.

```json
→ { "method": "mls_next_hpke_init_key", "params": {
      "mls_pubkey": "<hex-32>",
      "current_hpke_pubkey": "<hex-32>"
   }}
← { "result": { "hpke_pubkey": "<hex-32>" }}
```

`current_hpke_pubkey` is null for the first key (returns index 0).

### 11. `mls_hpke_decap`

HPKE decapsulation — DH using an HPKE init key identified by its
pubkey. Used during Welcome processing.

```json
→ { "method": "mls_hpke_decap", "params": {
      "hpke_pubkey": "<hex-32>",
      "kem_output": "<hex-32>"
   }}
← { "result": { "dh_result": "<hex-32>" }}
```

## Error codes

Standard JSON-RPC 2.0 error codes:

| Code | Constant | Meaning |
|------|----------|---------|
| -32601 | `ERR_UNKNOWN_METHOD` | Method not found |
| -32602 | `ERR_INVALID_PARAMS` | Invalid params (bad hex, unknown pubkey) |
| -32603 | `ERR_INTERNAL` | Internal error (signing failure, vault error) |

## Call flow: WhiteNoise boot sequence

This is the exact sequence WhiteNoise performs on startup when
`NOSTR_SA_SOCK` is set:

```
1. connect(NOSTR_SA_SOCK)
2. get_public_keys()                          → [pk1, pk2, ...]
3. for each pk:
     get_mls_pubkey(pk, null, 0x0001)         → mls_pk
     register SaMlsSigner(mls_pk)             → app.set_mls_signer_for_account()
     register SaHpkeBackend(mls_pk)           → app.set_vault_backend_for_account()
4. for each pk:
     login_external_signer(pk, SaAccountClient(pk))
```

After boot, WhiteNoise calls the daemon transparently through the
trait implementations:

| App operation | Daemon call(s) |
|---------------|---------------|
| Send chat message | `mls_sign` (commit signing) |
| Receive commit | `mls_hpke_dh` (UpdatePath decryption) |
| Join group (Welcome) | `mls_hpke_decap` |
| Publish key package | `mls_hpke_pubkey_at`, `mls_next_hpke_init_key` |
| Relay auth (NIP-44) | `nip44_encrypt`, `nip44_decrypt` |
| Event signing | `sign_event` |
| MLS leaf binding | `sign_account_identity_proof` |

## Test vectors

Four test users with deterministic BIP-39 mnemonics:

| User | Emails | Mnemonic |
|------|--------|----------|
| Alice | alice@atlanta.com, alice@home.com | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| Bob | bob@biloxi.com, bob@home.com | `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong` |
| Claire | claire@chicago.com, claire@home.com | `legal winner thank year wave sausage worth useful legal winner thank yellow` |
| David | david@denver.com, david@home.com | `letter advice cage absurd amount doctor acoustic avoid letter advice cage above` |

The integration test (`sa-client/tests/daemon_integration.rs`) uses
Alice's mnemonic and verifies all 11 methods produce identical output
to the in-process `KmLight` / `VaultAccountSigner`.

## What KeyMaster needs to implement

A `NostrServiceHandler` that handles all 11 methods. The handler
delegates to KeyMaster's BIP-32 vault for key derivation and signing.

### Mapping to KeyMaster internals

| Method | Crypto operation | KeyMaster vault call |
|--------|-----------------|---------------------|
| `get_public_keys` | — | List secp256k1 accounts at coin 1241 |
| `sign_event` | Schnorr (secp256k1) | `signSchnorr(hash)` |
| `sign_account_identity_proof` | Schnorr (secp256k1) | `signSchnorr(proof_hash)` |
| `nip44_encrypt` | ECDH + HKDF + ChaCha20-Poly1305 | `ecdh(peer)` + NIP-44 envelope |
| `nip44_decrypt` | ECDH + HKDF + ChaCha20-Poly1305 | `ecdh(peer)` + NIP-44 unwrap |
| `get_mls_pubkey` | — | Derive Ed25519 at MLS coin type |
| `mls_sign` | Ed25519 | `signEd25519(data)` |
| `mls_hpke_pubkey_at` | — | Derive X25519 at `(key_type, index)` |
| `mls_hpke_dh` | X25519 DH | `x25519(private, peer_public)` |
| `mls_hpke_decap` | X25519 DH | Same as `mls_hpke_dh` (init key variant) |
| `mls_next_hpke_init_key` | — | Advance init key index, derive X25519 |

### Key derivation paths

| Key type | Algorithm | BIP-32 path |
|----------|-----------|-------------|
| Nostr identity | secp256k1 | `44'/1241'/<mangle(email)>'/0'/0'` |
| MLS signing | Ed25519 | `44'/<mls-coin>'/<mangle(email)>'/<alg>/0'` |
| HPKE init keys | X25519 | `44'/<mls-coin>'/<mangle(email)>'/<alg>/<index>'` |
| HPKE enc keys | X25519 | `44'/<mls-coin>'/<mangle(email)>'/<alg>/<index>'` |

The `mangle()` function and MLS coin type are defined in
`keyvault-rs`. The reference implementation is in
`wn-kv-test/crates/core/src/km_light.rs`.

### Wire encoding note

The proven prototype uses **hex encoding** for all byte arrays
(consistent with Nostr convention). User story 03 specifies **base64**
for KeyMaster (consistent with KeyMaster's existing convention). This
is a transport-level detail — the sa-client library handles encoding
internally, so changing hex→base64 only requires updating the
serialization in `sa-rpc-types`.

### Acceptance criteria

1. KeyMaster's `NostrServiceHandler` handles all 11 methods
2. The existing `sa-client` integration test passes against
   KeyMaster's handler (after wiring the avatar transport)
3. WhiteNoise boots and functions identically (login, chat, group
   operations) with KeyMaster as the backend

## Reference code

| What | Location |
|------|----------|
| Wire types (JSON-RPC params/results) | `wn-kv-test/crates/rpc-types/src/lib.rs` |
| Reference daemon (all 11 handlers) | `wn-kv-test/crates/sa-daemon/src/main.rs` |
| Client library (trait impls) | `wn-kv-test/crates/sa-client/src/lib.rs` |
| Integration test (all 11 methods) | `wn-kv-test/crates/sa-client/tests/daemon_integration.rs` |
| Key manager (vault operations) | `wn-kv-test/crates/core/src/km_light.rs` |
| Vault signer (MLS + HPKE) | `wn-kv-test/crates/core/src/vault_signer.rs` |
| WhiteNoise boot sequence | `whitenoise-linux/src/backend.rs` |
| Avatar connection (KeyMaster perspective) | KeyMaster workspace, user story 03 |
