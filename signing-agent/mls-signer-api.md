# MLS Signer API

Status: Draft

An MLS signer is a service that holds MLS private key material and
performs cryptographic operations on behalf of a client. The client
never sees private keys — only public keys, signatures, and DH
results cross the boundary.

This document defines the functions an MLS signer must implement,
the setup handshake, and how a client integrates the signer with
the OpenMLS crypto provider.

---

## Functions

An MLS signer implements four functions: one for setup, three for
cryptographic operations.

### `get_mls_pubkey`

Returns the MLS Ed25519 public key for this account. The client
provides the ciphersuite and an optional device ID.

Must be called before any other `mls_*` function.

```
get_mls_pubkey(device_id, ciphersuite) → ed25519_public_key
```

**Input:**

| Param | Type | Description |
|---|---|---|
| `device_id` | string or null | Device identifier. Null for shared mode (all devices get the same key). Non-null for device-bound mode (each device gets a unique key). |
| `ciphersuite` | string | MLS ciphersuite. `"0x0001"` = Ed25519 + X25519 + AES-128-GCM + SHA-256. |

**Output:** Ed25519 public key, 32 bytes hex-encoded (64 hex chars).

**How the signer uses the inputs:**

The signer combines the device ID with the account identity to
derive the key. For an HD-based signer like KeyMaster:

- Shared: `mangle("alice@atlanta.com")` → same key on all devices
- Device-bound: `mangle("alice@atlanta.com:cpu_xyz")` → unique key

The ciphersuite determines which algorithm branch to use. With
`0x0001`, the signer derives Ed25519 keys. A different ciphersuite
would require different key types (e.g., P-256 for `0x0002`).

The signer does not need to know what a "device" is or how the
client obtained the device ID. It just mixes the string into the
derivation path.

**Example — shared mode:**
```
→ get_mls_pubkey(null, "0x0001")
← "a1b2c3...64 hex chars"
```

**Example — device-bound:**
```
→ get_mls_pubkey("cpu_xyz", "0x0001")
← "d4e5f6...64 hex chars"
```

**Error conditions:**
- Ciphersuite not supported.
- Account does not have MLS keys configured.

---

### `mls_sign`

Signs arbitrary data with the MLS Ed25519 signing key.

```
mls_sign(data) → ed25519_signature
```

**Input:**

| Param | Type | Description |
|---|---|---|
| `data` | hex string | Raw bytes to sign. |

**Output:** Ed25519 signature, 64 bytes hex-encoded (128 hex chars).

**Notes:**
- Most frequently called function. Used for every MLS commit,
  proposal, application message, and KeyPackage signature.
- The data is TLS-serialized MLS content — the signer does not
  need to parse or understand it.
- Uses the key established by the prior `get_mls_pubkey` call.

---

### `mls_next_hpke_init_key`

Returns the next HPKE init key (X25519 public key) for creating a
new KeyPackage.

The client passes the current HPKE public key read from the relay
(from the most recently published KeyPackage). The signer locates
that key in its HD derivation tree, advances to the next index,
and returns the new public key.

If no KeyPackage exists on the relay yet (new account), the client
passes null/empty to get the first key (index 0).

```
mls_next_hpke_init_key(current_hpke_pubkey) → x25519_public_key
```

**Input:**

| Param | Type | Description |
|---|---|---|
| `current_hpke_pubkey` | hex string or null | Current HPKE public key from the relay. Null for first key. |

**Output:** X25519 public key, 32 bytes hex-encoded (64 hex chars).

**Example — first KeyPackage (new account):**
```
→ mls_next_hpke_init_key(null)
← "d4e5f6...64 hex chars"
```

**Example — subsequent KeyPackage:**
```
→ mls_next_hpke_init_key("a1b2c3...64 hex chars")
← "d4e5f6...64 hex chars"
```

**Notes:**
- The signer manages indices internally. The client never sees
  index numbers — only public keys.
- The relay is the source of truth for the current HPKE state.
  The signer does not need to persist a counter; it derives the
  index from the public key the client provides.
- For HD-based signers: given the current public key, derive
  forward from index 0 until the key matches, then return
  index+1. The search space is bounded (typically small).

**Error conditions:**
- `current_hpke_pubkey` does not match any derived key (client
  and signer are out of sync).

---

### `mls_hpke_decap`

Performs X25519 key agreement using the HPKE init key that matches
the given public key. Returns the raw DH shared secret.

Used when processing an MLS Welcome message. The Welcome contains
a KEM ciphertext (an ephemeral X25519 public key from the sender).
The client passes the HPKE public key that was in the KeyPackage
used for this Welcome. The signer finds the matching private key
and performs DH.

```
mls_hpke_decap(hpke_pubkey, kem_output) → dh_shared_secret
```

**Input:**

| Param | Type | Description |
|---|---|---|
| `hpke_pubkey` | hex string | The HPKE init public key from the KeyPackage (32 bytes). |
| `kem_output` | hex string | The KEM encapsulation output (sender's ephemeral X25519 public key, 32 bytes). |

**Output:** Raw DH shared secret, 32 bytes hex-encoded (64 hex chars).

This is `X25519(sk_init, kem_output)` where `sk_init` is the
private key corresponding to `hpke_pubkey` — the raw elliptic
curve DH result, NOT the final HPKE shared secret.

**Client-side completion:**
```
kem_context = kem_output || pk_init || pk_sender
shared_secret = ExtractAndExpand(dh_result, kem_context)
```

The HKDF step uses only the DH result and public data. No private
key is needed. The signer never sees the final shared secret used
for decryption.

**Error conditions:**
- `hpke_pubkey` does not match any derived key.
- `kem_output` is not a valid X25519 public key (wrong length).

---

## Function Summary

| Function | Input | Output | Stateful |
|---|---|---|---|
| `get_mls_pubkey` | device_id, ciphersuite | Ed25519 pubkey | Yes (establishes MLS session) |
| `mls_sign` | data bytes | Ed25519 signature | No |
| `mls_next_hpke_init_key` | current HPKE pubkey or null | X25519 pubkey | No |
| `mls_hpke_decap` | HPKE pubkey, kem_output | DH shared secret | No |

Note: `mls_next_hpke_init_key` is marked "No" for stateful because
the signer derives the next key from the input — it does not need
to maintain an internal counter. The relay is the source of truth.

---

## Setup Flow

```
Client (WN)                             Signer (KM)
  │                                        │
  │  1. connect()                          │
  │     (NIP-46, NIP-55, etc.)             │
  │ ─────────────────────────────────────► │
  │                                        │
  │  User selects account in KM            │
  │  ◄── nostr_pubkey (account id) ─────── │
  │                                        │
  │  2. get_mls_pubkey(device_id, "0x0001")│
  │ ─────────────────────────────────────► │
  │                                        │
  │  ◄── ed25519_pubkey ────────────────── │
  │                                        │
  │  3. Client reads current HPKE pubkey   │
  │     from relay (or null if new)        │
  │                                        │
  │  4. Client configures CryptoProvider   │
  │     with ed25519_pubkey and signer ref │
  │                                        │
  │  5. Client creates MDK with the        │
  │     configured CryptoProvider          │
  │                                        │
  │  Ready for MLS operations.             │
  │                                        │
```

### Step 1 — Connect

Transport-dependent. Could be:
- NIP-46 `connect` over Nostr relays (desktop)
- NIP-55 Android intent (mobile)
- Direct function call (in-process, testing)

The user selects an account inside KeyMaster. The Nostr pubkey is
returned and serves as the account identifier in Whitenoise.

### Step 2 — Get MLS Public Key

The client calls `get_mls_pubkey` with:

- **`device_id`** — the client knows its own device. If the user
  wants device-bound MLS keys, the client passes its device ID.
  If shared mode, it passes null. KeyMaster does not need to know
  what device the client is running on — it just mixes the string
  into the derivation path.
- **`ciphersuite`** — determines which key types to derive.

The returned Ed25519 public key is used for KeyPackages and
AccountIdentityProof.

If `get_mls_pubkey` fails (unsupported ciphersuite, no MLS keys),
the client falls back to local RustCrypto for MLS key generation.
Nostr signing can still go through the signer.

### Step 3 — Read HPKE State from Relay

The client checks the relay for published KeyPackage events
(kind-30443) for this account. If a KeyPackage exists, the client
extracts the HPKE init public key. If no KeyPackage exists (new
account), the current HPKE pubkey is null.

This pubkey will be passed to `mls_next_hpke_init_key` when the
client needs to create a new KeyPackage.

### Step 4 — Configure CryptoProvider

The client creates a `KeyMasterCryptoProvider` that wraps
`RustCrypto` and overrides asymmetric operations:

```
KeyMasterCryptoProvider {
    signer: <KeyMaster connection>,
    signing_key: <from get_mls_pubkey>,
    current_hpke_pubkey: <from relay or null>,
    default_crypto: RustCrypto,
}
```

### Step 5 — Create MDK

The MDK is constructed with the custom crypto provider:

```
MDK::builder(storage)
    .with_crypto(keymaster_crypto)
    .build()
```

From this point, all MLS operations (create group, send message,
process welcome, etc.) flow through the signer for asymmetric
operations and through RustCrypto for everything else.

---

## Integration with OpenMLS

The `KeyMasterCryptoProvider` implements the OpenMLS `OpenMlsCrypto`
trait. It routes private-key operations to the signer and passes
everything else to `RustCrypto`:

| OpenMLS calls... | Provider routes to... | Why |
|---|---|---|
| `signature_key_gen()` | returns pubkey from `get_mls_pubkey` | Private key stays in signer |
| `sign()` | `mls_sign` | Private key stays in signer |
| `verify()` | local RustCrypto | Public key only |
| `hpke_derive_keypair()` | `mls_next_hpke_init_key` | Private key stays in signer |
| `hpke_open()` | `mls_hpke_decap` + local HKDF | Signer does DH, client does KDF |
| `hpke_seal()` | local RustCrypto | Recipient's public key only |
| `aead_encrypt()` | local RustCrypto | Symmetric key from MLS schedule |
| `aead_decrypt()` | local RustCrypto | Symmetric key from MLS schedule |
| `hkdf_extract()` | local RustCrypto | Symmetric KDF |
| `hkdf_expand()` | local RustCrypto | Symmetric KDF |
| `hash()` | local RustCrypto | No key involved |
| `random_bytes()` | local RustCrypto | OS CSPRNG |

### Private Key Handles

OpenMLS stores "private keys" in its storage provider. With a remote
signer, there are no real private keys on the client. Instead, the
crypto provider stores handles:

- **Signing "private key"**: A sentinel byte sequence that the
  provider recognizes. When `sign()` receives this sentinel as the
  key parameter, it ignores it and calls `mls_sign` on the signer.

- **HPKE "private key"**: The HPKE public key itself, stored as
  the "private key" bytes. When `hpke_open()` receives this, the
  provider passes it to `mls_hpke_decap(hpke_pubkey, kem_output)`
  on the signer. The signer finds the matching private key
  internally.

This keeps OpenMLS's internal key lifecycle management working
without modification — it stores, retrieves, and passes "keys" as
usual, but the actual cryptographic operations happen remotely.

---

## Security Properties

**Private key isolation.** Ed25519 signing keys and X25519 HPKE
init keys never leave the signer. The protocol transmits only
public keys, signatures, and raw DH results.

**DH result ≠ decryption key.** The `mls_hpke_decap` result is the
raw X25519 DH output, not the HPKE shared secret. The HKDF
derivation step (ExtractAndExpand) happens on the client using
public context data. An attacker intercepting the DH result cannot
derive the decryption key without the KEM context.

**No index exposure.** The client never sees HPKE key indices.
It works only with public keys. Index management is entirely
internal to the signer's HD derivation tree.

**Relay as source of truth.** The current HPKE state is determined
by what's published on the relay, not by internal signer state.
This makes recovery straightforward — read the relay, pass the
pubkey to the signer, continue.

**Client controls device binding.** The signer does not decide
whether keys are shared or device-bound. The client passes its
device ID (or null) to `get_mls_pubkey`. The signer just derives
whatever it's told. This keeps the signer simple and prevents it
from needing to know about client devices.

**Stateless signing.** `mls_sign` is stateless — safe for
concurrent access from any number of clients.

---

## Error Conditions

| Error | Function | Meaning |
|---|---|---|
| `unsupported ciphersuite` | `get_mls_pubkey` | Signer cannot use the requested ciphersuite |
| `not mls capable` | `get_mls_pubkey` | Account has no MLS keys configured |
| `unknown hpke key` | `mls_next_hpke_init_key`, `mls_hpke_decap` | Public key does not match any derived key |
| `invalid payload` | `mls_sign`, `mls_hpke_decap` | Hex decoding failed or wrong length |
| `signing failed` | `mls_sign` | Internal crypto error |
| `session not established` | `mls_sign`, `mls_next_hpke_init_key`, `mls_hpke_decap` | `get_mls_pubkey` was not called first |

---

## Signer Implementation Notes

The signer is responsible for:

1. **Key derivation.** Mapping the account identity and device ID
   to the correct cryptographic keys. For KeyMaster, this means
   combining the identity string with the device ID (if provided),
   computing `mangle()`, and constructing the BIP-32 derivation
   path. The client knows none of this.

2. **HPKE key lookup.** Given a public key from the client, finding
   the matching index in the HD derivation tree. For HD-based
   signers, this means deriving keys from index 0 forward until the
   public key matches. The search space is bounded by the number of
   KeyPackages ever created (typically small — tens, not thousands).

The signer does NOT need to:
- Understand MLS protocol messages
- Parse TLS-serialized MLS content
- Know about MLS groups, epochs, or ratchet trees
- Manage any MLS protocol state
- Persist an HPKE index counter (the relay is the source of truth)
- Know what device the client is running on (client passes device ID)
- Decide shared vs device-bound mode (client's choice)

It is a signing and key agreement oracle. The MLS protocol logic
lives entirely in the client (via OpenMLS / mdk-core).
