# KeyVault-Based MLS Key Derivation

Status: Draft

This document describes how the DWDC KeyVault deterministic key derivation
system can generate MLS keys alongside Nostr keys from a single seed, and
the advantages and tradeoffs of this approach compared to the current
Whitenoise design where MLS keys are randomly generated and stored in an
encrypted vault.

## Background

### Current Whitenoise Design

Whitenoise generates MLS keys independently of the Nostr identity:

1. The user imports an nsec (secp256k1 scalar) into an encrypted vault
   (`vault.db`), protected by Argon2id key derivation from a password.
2. An Ed25519 MLS signing key is randomly generated per device and stored
   in an OpenMLS SQLCipher database.
3. X25519 HPKE init keys are randomly generated per KeyPackage.
4. An AccountIdentityProof (BIP-340 Schnorr signature) binds the Nostr
   npub to the MLS Ed25519 public key.

This requires:

- a password-encrypted vault for the nsec;
- a SQLCipher database for MLS private keys;
- backup and sync of both stores to recover on a new device;
- the user to remember the vault password.

### The KeyVault Alternative

The DWDC KeyVault derives all keys deterministically from a single BIP-39
mnemonic using BIP-32 hierarchical derivation. The same seed already
produces keys for SSH, OpenPGP, Nostr, Bitcoin, X.509, and WireGuard.
Adding MLS is another protocol branch in the same tree.

Recovery requires only the mnemonic. No vault, no encrypted database, no
password-based KDF at startup. All keys — Nostr and MLS — are
re-derivable from the same 12 or 24 words.

---

## Derivation Path Structure

The KeyVault uses a 5-level BIP-32 derivation path:

```
m / purpose' / coin_type' / identity' / algorithm' / config'
    level 0    level 1      level 2     level 3      level 4
```

All levels are hardened. The fields are:

| Level | Name | Bits | Encoding |
|---|---|---|---|
| 0 | purpose | 31 | Fixed: `44` |
| 1 | coin_type | 31 | Protocol enum |
| 2 | identity | 31 | `mangle(identity_string)` — SHA-256 truncated to 31 bits |
| 3 | algorithm | 31 | `alg(15) \| variant(8) \| role(8)` |
| 4 | config | 31 | `csprng(7) \| index(24)` |

### Protocol Assignment

MLS receives a new entry in the Protocol enum:

| Protocol | Coin Type |
|---|---|
| Bitcoin | 0 |
| Nostr | 1237 |
| SSH | 1238 |
| OpenPGP | 1239 |
| X.509 | 1240 |
| WireGuard | 1241 |
| **MLS** | **1242** |

### Algorithm Constants

The existing KeyVault algorithm constants apply:

| Constant | Value | Curve | Use in MLS |
|---|---|---|---|
| `ALG_SCHNORR` | 0 | secp256k1 | Not used for MLS (Nostr branch only) |
| `ALG_ED25519` | 1 | Ed25519 / X25519 | MLS signing and HPKE init keys |

Ed25519 and X25519 share the same seed material. The KeyVault already
implements Ed25519 signing (`FN_SIGN`) and X25519 key agreement
(`FN_KEY_AGREEMENT`) from the same derived 32-byte seed, following the
standard Ed25519-to-X25519 conversion (SHA-512 hash with clamping).

### Role Constants for MLS

The `role` byte in level 3 distinguishes key purpose within the MLS
protocol:

| Role | Value | Purpose |
|---|---|---|
| `SIGN` | 0 | MLS signing key (Ed25519) |
| `HPKE` | 1 | HPKE init key for KeyPackages (X25519, derived from Ed25519 seed) |

---

## Identity and Device Modes

The identity level (level 2) determines whether MLS keys are per-person
or per-device. The user chooses at identity creation time.

### Shared Mode (No Device ID)

All devices derive the same MLS identity from the same seed:

```
m / 44' / 1242' / mangle("alice@atlanta.com")' / ED25519|0|SIGN' / 0|0'
```

The mangle input is the same identity string used for Nostr and other
protocols:

| Protocol | Level 2 | Result |
|---|---|---|
| Nostr | `mangle("alice@atlanta.com")` | `0x748b0a69` |
| MLS | `mangle("alice@atlanta.com")` | `0x748b0a69` |

Every device with the mnemonic derives the same MLS signing key. All
devices are the same MLS leaf in every group. Implications:

- Any device can rejoin groups, decrypt history, continue sessions.
- No per-device state to back up beyond the mnemonic itself.
- Only one device should actively commit to a group at a time, because
  two devices sharing the same MLS leaf cannot independently advance the
  epoch without coordination.

### Device-Bound Mode (Device ID Mixed In)

Each device derives a distinct MLS identity by mixing a hardware
identifier into the mangle input:

```
m / 44' / 1242' / mangle("alice@atlanta.com:cpu_xyz")' / ED25519|0|SIGN' / 0|0'
```

The device ID is concatenated with a separator before mangling:

```java
int mlsIdentity = Bip32KeyDerivator.mangle(identity + ":" + deviceId);
```

Each device gets a different 31-bit identity hash:

| Device | Level 2 | MLS Leaf |
|---|---|---|
| Alice's laptop | `mangle("alice@atlanta.com:cpu_abc")` | Leaf A |
| Alice's phone | `mangle("alice@atlanta.com:cpu_xyz")` | Leaf B |

The Nostr identity remains the same across devices — only the MLS branch
is device-specific:

| Protocol | Level 2 | Shared? |
|---|---|---|
| Nostr | `mangle("alice@atlanta.com")` | Same on all devices |
| MLS (laptop) | `mangle("alice@atlanta.com:cpu_abc")` | Laptop only |
| MLS (phone) | `mangle("alice@atlanta.com:cpu_xyz")` | Phone only |

Implications:

- Each device is a separate MLS leaf with independent signing keys.
- Standard MLS multi-device model: "Alice's laptop" and "Alice's phone"
  are distinct group members.
- Both devices can commit independently without epoch conflicts.
- Losing a device requires removing that leaf from all groups. The keys
  can still be re-derived from the mnemonic if the device ID is known.

### The User's Choice

The KeyVault does not enforce either mode. The identity template
determines what string is passed to `mangle()`:

```
Template "mls-shared":
  MLS identity = "{identity}"

Template "mls-device-bound":
  MLS identity = "{identity}:{device_id}"
```

The vault, the derivation code, the path structure, the service
handlers — none of them change between modes. The choice is encoded
entirely in the identity string.

---

## Concrete Derivation Paths

### Nostr Keys (Existing)

```
Nostr signing (Schnorr, secp256k1):
  m / 44' / 1237' / mangle("alice@atlanta.com")' / SCHNORR|0|0' / 0|0'
  KeyVault: FN_SIGN        -> BIP-340 Schnorr signature
  KeyVault: FN_GET_PUBLIC_KEY -> 32-byte x-only public key
  KeyVault: FN_KEY_AGREEMENT  -> NIP-44 ECDH shared secret
```

### MLS Keys (Shared Mode)

```
MLS signing (Ed25519):
  m / 44' / 1242' / mangle("alice@atlanta.com")' / ED25519|0|SIGN(0)' / 0|0'
  KeyVault: FN_SIGN           -> 64-byte Ed25519 signature
  KeyVault: FN_GET_PUBLIC_KEY -> 32-byte Ed25519 public key

MLS HPKE init key #0 (X25519, derived from Ed25519 seed):
  m / 44' / 1242' / mangle("alice@atlanta.com")' / ED25519|0|HPKE(1)' / 0|0'
  KeyVault: FN_GET_PUBLIC_KEY -> 32-byte X25519 public key
  KeyVault: FN_KEY_AGREEMENT  -> HPKE decapsulation

MLS HPKE init key #1:
  m / 44' / 1242' / mangle("alice@atlanta.com")' / ED25519|0|HPKE(1)' / 0|1'
                                                                           ^
                                                              index increments

MLS HPKE init key #N:
  m / 44' / 1242' / mangle("alice@atlanta.com")' / ED25519|0|HPKE(1)' / 0|N'
```

### MLS Keys (Device-Bound Mode)

```
MLS signing — laptop:
  m / 44' / 1242' / mangle("alice@atlanta.com:cpu_abc")' / ED25519|0|SIGN' / 0|0'

MLS signing — phone:
  m / 44' / 1242' / mangle("alice@atlanta.com:cpu_xyz")' / ED25519|0|SIGN' / 0|0'

MLS HPKE init key #3 — laptop:
  m / 44' / 1242' / mangle("alice@atlanta.com:cpu_abc")' / ED25519|0|HPKE' / 0|3'
```

### AccountIdentityProof

The Nostr key signs a proof binding the npub to the MLS Ed25519 public
key. Both keys are derived from the same seed, from different branches:

```
Nostr branch:  m/44'/1237'/mangle(alice)'/SCHNORR|0|0'/0|0'  -> alice_npub
MLS branch:    m/44'/1242'/mangle(alice)'/ED25519|0|SIGN'/0|0' -> alice_ed25519.pub

AccountIdentityProof:
  canonical = "marmot.account-identity-proof.v1" || fields
  digest = SHA-256(canonical)
  proof_sig = BIP-340_Schnorr_Sign(nostr_key, digest)

  "I, alice_npub, authorize alice_ed25519.pub as my MLS signing key"
```

The proof works identically to the current design. The only difference
is that both keys are deterministic rather than one being imported and
the other randomly generated.

---

## HPKE Init Key Management

MLS requires that each HPKE init key is used at most once. A KeyPackage
published to relays contains one init key; when that KeyPackage is
consumed by a Welcome, the init key is spent.

With deterministic derivation, init keys are produced by incrementing the
index in level 4:

```
KeyPackage #0:  m / 44' / 1242' / identity' / ED25519|0|HPKE' / 0|0'
KeyPackage #1:  m / 44' / 1242' / identity' / ED25519|0|HPKE' / 0|1'
KeyPackage #2:  m / 44' / 1242' / identity' / ED25519|0|HPKE' / 0|2'
...
KeyPackage #N:  m / 44' / 1242' / identity' / ED25519|0|HPKE' / 0|N'
```

The 24-bit index field supports up to 16,777,216 KeyPackages per
identity, which is sufficient for any practical use.

The counter value should be persisted locally so that a device does not
re-derive an index it has already used. It can be stored in the
KeyMaster metadata or in the Whitenoise account database:

```json
{
  "path": "m/44'/1242'/748b0a69'/65537'/0'",
  "metadata": {
    "next_hpke_index": 5
  }
}
```

However, the counter is recoverable. KeyPackages are published as
kind-30443 (replaceable) Nostr events on relays. The HPKE init public
key is embedded in each published KeyPackage. On recovery — whether
from a fresh device, after a wipe, or on a second device in shared
mode — the device can:

1. Query relays for its own published kind-30443 events.
2. Extract the HPKE init public keys from those KeyPackages.
3. Derive HPKE public keys at incrementing indices from the KeyVault
   (`FN_GET_PUBLIC_KEY` at each candidate index) until it finds the
   index that produced the last published key.
4. Resume from the next unused index.

This is a linear scan, but the search space is small — typically tens
of KeyPackages, not millions. The derivation is fast (one HKDF + one
X25519 scalar-base-multiply per candidate).

In shared mode, multiple devices benefit from this: any device can
read the published KeyPackages (they are public Nostr events), derive
forward from the highest published index, and continue publishing
without collisions. The relay is the shared coordination point — no
device-to-device sync channel is needed.

In device-bound mode, each device has its own identity hash and its
own published KeyPackages, so the same relay-based recovery works
independently per device.

If relays have pruned old KeyPackage events and the local counter is
lost, the device can conservatively skip ahead to a safe index range
(e.g., current index + 1000) to avoid reuse. The cost is a gap in
the index sequence, which has no protocol impact.

---

## What Changes from the Current Whitenoise Design

### Components Eliminated

| Current Component | Purpose | Replacement |
|---|---|---|
| `vault.db` | Encrypted nsec storage | Mnemonic (user remembers or backs up) |
| Argon2id KDF | Derive vault encryption key from password | Not needed |
| XChaCha20Poly1305 vault encryption | Encrypt/decrypt vault contents | Not needed |
| Vault password | User authentication at startup | Not needed for key derivation |
| `Ed25519::generate()` | Random MLS signing key | `vault.execute(FN_GET_PUBLIC_KEY, null, mls_sign_path)` |
| `X25519::generate()` | Random HPKE init key | `vault.execute(FN_GET_PUBLIC_KEY, null, mls_hpke_path)` |
| OpenMLS SQLCipher DB (for signing key) | Store randomly generated private keys | Keys re-derived on demand |

### Components Unchanged

| Component | Why Unchanged |
|---|---|
| AccountIdentityProof | Same structure, same signature scheme, same binding semantics |
| MLS epoch key schedule | Entirely internal to MLS; KeyVault provides only the initial signing and HPKE keys |
| MLS ratchet tree | Unchanged; leaf nodes contain derived public keys instead of random ones |
| Per-sender AES-128-GCM ratchets | Derived by MLS key schedule, not by KeyVault |
| Kind-445 transport encryption | Uses MLS-exported group_event_key, unchanged |
| NIP-59 Welcome wrapping | Uses Nostr key for NIP-44 ECDH, unchanged |
| Ephemeral secp256k1 keys for kind-445 | Still randomly generated per event; not derived from seed |
| OpenMLS state storage | OpenMLS still needs to persist epoch state, ratchet tree, etc. |

### Components Modified

| Component | Change |
|---|---|
| OpenMLS crypto provider | Must delegate Ed25519 signing and X25519 key generation to KeyVault instead of generating randomly |
| Key generation flow | Replace `Ed25519::generate()` with `vault.execute(FN_GET_PUBLIC_KEY, ...)` at the MLS signing path |
| KeyPackage construction | HPKE init keys derived from KeyVault with incrementing index |
| Account setup | No vault creation, no password prompt; user provides mnemonic |

---

## Integration with OpenMLS

OpenMLS uses a `CryptoProvider` trait for all cryptographic operations.
The integration point is a custom provider that routes signing and key
generation through the KeyVault while leaving symmetric operations
(AES-128-GCM, HKDF, etc.) to the default implementation.

Operations that must be delegated to KeyVault:

| OpenMLS Operation | KeyVault Call |
|---|---|
| Generate MLS signing keypair | `execute(FN_GET_PUBLIC_KEY, null, mls_sign_path)` |
| Sign MLS message | `execute(FN_SIGN, payload, mls_sign_path)` |
| Generate HPKE init keypair | `execute(FN_GET_PUBLIC_KEY, null, mls_hpke_path)` |
| HPKE decapsulate (Welcome) | `execute(FN_KEY_AGREEMENT, enc, mls_hpke_path)` |

Operations that remain in the default provider:

| Operation | Reason |
|---|---|
| HKDF-SHA256 | Symmetric, no private key involved |
| AES-128-GCM | Symmetric, key from MLS key schedule |
| SHA-256 | Hash, no key involved |
| HPKE encapsulate | Uses recipient's public key only |
| Path secret derivation | Internal MLS key schedule |

The KeyVault never sees epoch secrets, sender ratchet keys, or message
plaintext. It provides the two asymmetric key operations that anchor the
MLS identity (signing) and enable group joining (HPKE init key
decapsulation).

---

## Advantages

### Single Recovery Secret

The mnemonic recovers all keys across all protocols: Nostr identity, SSH
keys, GPG keys, Bitcoin keys, and MLS keys. No separate vault backup, no
database export, no password to remember. A user who loses a device
needs only the mnemonic to re-derive every key.

### No Encrypted Storage for Key Material

The vault.db, its Argon2id KDF, and its XChaCha20Poly1305 encryption are
eliminated. There is no password-derived key that could be brute-forced
from a stolen vault file. The mnemonic is the only secret, and it is not
stored on disk by the KeyVault.

### Deterministic Cross-Device Keys (Shared Mode)

In shared mode, every device with the mnemonic derives the same MLS
signing key. A user can set up a new device and immediately have the
same MLS identity without transferring key material. The
AccountIdentityProof is deterministic too — it can be reconstructed
because both the Nostr key and the MLS key are derivable.

### Unified Security Boundary

The KeyVault's security model — keys never leave the vault, callers
receive only signatures and public keys — applies uniformly to MLS. The
same policy, approval, and audit infrastructure that governs SSH signing
and Nostr event signing also governs MLS operations.

### Protocol Independence

Adding MLS does not require architectural changes to the KeyVault or
KeyMaster. It is a new coin type (1242), a new service handler, and new
entries in the key metadata store. The derivation engine, path encoding,
and security boundary are reused without modification.

### User Choice on Device Binding

The user decides whether MLS keys are shared across devices or bound to
specific hardware. The decision is encoded in the identity string passed
to `mangle()`. The KeyVault treats both modes identically — no feature
flags, no conditional logic, no separate code paths.

---

## Tradeoffs

### Seed Compromise Scope

With randomly generated MLS keys, compromising the Nostr nsec does not
reveal the MLS signing key. They are independent secrets stored in
separate locations.

With KeyVault derivation, compromising the mnemonic reveals all derived
keys across all protocols — Nostr, MLS, SSH, GPG, Bitcoin. The mnemonic
is a single point of compromise.

This is the same tradeoff the KeyVault already makes for every other
protocol it supports. The mitigation is to protect the mnemonic itself:
never store it digitally, use a hardware wallet or secure enclave for
the KeyVault process, and rely on the KeyMaster's authorization boundary
to prevent unauthorized use even if the vault process is accessible.

The MLS key schedule provides forward secrecy for message content
regardless of how the signing key was generated. Compromising the MLS
signing key allows impersonation (forging new commits and messages) but
does not reveal past epoch secrets that have been deleted from device
memory.

### HPKE Init Key Counter State

Randomly generated HPKE init keys are stateless — each one is
independent. Deterministically derived init keys require a monotonic
counter to avoid reuse. The counter is cached locally for efficiency,
but it is recoverable from Nostr relays: published KeyPackages
(kind-30443 events) contain the HPKE init public key, and the device
can scan derivation indices to find the last published one.

This recovery depends on relay availability and retention. If relays
have pruned old KeyPackage events, the device skips ahead by a safe
margin. The cost is a gap in the index sequence, which has no protocol
impact — only wasted derivation indices.

### Device ID Stability

In device-bound mode, the MLS identity depends on a hardware identifier
(e.g., CPU serial number). If the hardware identifier changes — through
motherboard replacement, VM migration, or platform-specific API
differences — the device derives a different MLS identity and cannot
rejoin groups as its previous self.

Mitigations:

- Use a stable identifier that survives hardware changes (e.g., a
  machine ID written to disk on first boot).
- Accept that hardware replacement means the old device-leaf must be
  removed from groups and a new device-leaf added.
- Use shared mode if device binding is not needed.

### Shared Mode Sender Ratchet Coordination

In shared mode, multiple devices share the same MLS leaf and signing
key. Concurrent commits from different members are normal MLS
behavior — a commit based on a stale epoch is rejected by the group,
and the sender re-syncs and retries.

The shared-mode-specific consideration is sender ratchet state. MLS
maintains a per-leaf sender ratchet that advances with each application
message. If device A sends a message and advances the ratchet, device B
does not see that advancement. If device B then sends a message using
the old ratchet position, recipients who already processed device A's
message will attempt decryption with the wrong ratchet key.

In practice this requires two devices sending messages on the same
group at nearly the same time. Devices that observe each other's
messages via the relay can stay synchronized. For users who need
truly simultaneous multi-device activity, device-bound mode gives each
device its own leaf and independent ratchet state.

### OpenMLS Integration Effort

OpenMLS expects to own key generation through its `CryptoProvider` trait.
Replacing the default random key generation with deterministic KeyVault
derivation requires a custom provider implementation. This is the
primary integration work — the provider must route asymmetric operations
to the KeyVault while leaving symmetric operations to the default
implementation.

The boundary is clean (four operations to delegate), but the
implementation must handle the KeyVault's path-based addressing and
translate between OpenMLS key types and KeyVault byte arrays.

---

## Implementation in Whitenoise

The integration should live in `whitenoise-rs` (the core library), not
in any specific client. This makes the KeyVault backend available to
every frontend (`whitenoise-linux`, `whitenoise` Flutter, future
clients) without duplicating logic.

### Existing Architecture

Whitenoise already supports two signing backends through `AccountType`:

```rust
pub enum AccountType {
    Local,      // Private key stored in platform keyring (SecretsStore)
    External,   // External signer (NIP-55/Amber), no private key stored
}
```

The key management stack has three layers:

| Layer | Current Implementation | Purpose |
|---|---|---|
| Nostr signing | `SecretsStore` (keyring) or `NostrSigner` trait (external) | Sign Nostr events |
| MLS crypto | `mdk-core` with `MdkSqliteStorage` (SQLCipher) | MLS signing, HPKE, key schedule |
| Secret storage | Platform keyring + SQLCipher DB (+ vault.db on Linux desktop) | Persist private keys |

### Adding the KeyMaster Backend

The KeyMaster is a third `AccountType` — neither locally generated keys
nor an external signer app, but deterministically derived keys from the
KeyVault:

```rust
pub enum AccountType {
    Local,      // Private key stored in platform keyring
    External,   // External signer (NIP-55/Amber)
    KeyMaster,  // Keys derived from KeyVault mnemonic
}
```

#### Nostr Layer: `NostrSigner` Implementation

The `nostr-sdk` `NostrSigner` trait is the existing abstraction for
Nostr signing. A KeyMaster backend implements this trait by delegating
to the KeyVault:

```rust
struct KeyVaultSigner {
    vault: KeyVaultClient,    // Connection to KeyVault service
    nostr_path: Vec<u32>,     // m/44'/1237'/mangle(id)'/SCHNORR|0|0'/0|0'
}

impl NostrSigner for KeyVaultSigner {
    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event> {
        let hash = unsigned.id.as_bytes();  // 32-byte event hash
        let sig = self.vault.execute(FN_SIGN, hash, &self.nostr_path)?;
        // Construct signed event from sig bytes
    }

    async fn get_public_key(&self) -> Result<PublicKey> {
        let pubkey = self.vault.execute(FN_GET_PUBLIC_KEY, &[], &self.nostr_path)?;
        // Parse 32-byte x-only public key
    }
}
```

This plugs into the existing `get_signer_for_account()` call that
Whitenoise already uses for every Nostr operation (event signing,
relay list publishing, metadata publishing, etc.). No changes needed
to any calling code.

#### MLS Layer: Custom Crypto Provider

The MLS integration point is `mdk-core`, which wraps OpenMLS. OpenMLS
uses a `CryptoProvider` trait for cryptographic operations. The
KeyVault backend provides a custom provider that delegates the four
asymmetric operations to the KeyVault while leaving symmetric
operations (AES-128-GCM, HKDF, SHA-256) to the default implementation:

```rust
struct KeyVaultMlsCryptoProvider {
    vault: KeyVaultClient,
    sign_path: Vec<u32>,      // m/44'/1242'/mangle(id)'/ED25519|0|SIGN'/0|0'
    hpke_path_base: Vec<u32>, // m/44'/1242'/mangle(id)'/ED25519|0|HPKE'/0|
    next_hpke_index: AtomicU32,
    default_provider: DefaultCryptoProvider,
}
```

The `MDK::new()` constructor would accept an optional crypto provider
override, or `mdk-core` would expose a builder that allows injecting
one.

#### Secret Storage Layer: Nothing to Store

With KeyMaster, neither `SecretsStore` (keyring) nor `vault.db` is
needed for key material. The mnemonic is held by the KeyMaster process,
which the application connects to as a service. The only state to
persist is:

- The `AccountType::KeyMaster` designation in the account database
- The identity string used for `mangle()` (e.g.,
  `"alice@atlanta.com"` or `"alice@atlanta.com:cpu_xyz"`)
- The HPKE init key counter (next unused index)
- The coin type / path metadata for the KeyVault

OpenMLS still needs its SQLCipher database for epoch state, ratchet
trees, and message queues. That does not change.

### Client Selection

The choice of backend is a client-level decision made at account
creation or login time:

```
whitenoise-linux:
  ├─ Login with nsec + vault password  → AccountType::Local
  ├─ Login with KeyMaster mnemonic     → AccountType::KeyMaster
  └─ Login with external signer        → AccountType::External

whitenoise (Flutter mobile):
  ├─ Login with nsec                   → AccountType::Local
  ├─ Login with Amber (NIP-55)         → AccountType::External
  └─ Login with KeyMaster              → AccountType::KeyMaster (if available)
```

The core library does not care which backend is active. It calls
`get_signer_for_account()` and gets back something that implements
`NostrSigner`. It calls `create_mdk_for_account()` and gets back an
`MDK` configured with the right crypto provider. The branching logic is
entirely in the account setup path.

### What Changes in Each Crate

| Crate | Change |
|---|---|
| `whitenoise-rs` | Add `AccountType::KeyMaster`, implement `NostrSigner` for KeyVault, provide `KeyVaultMlsCryptoProvider`, wire into `get_signer_for_account()` and `create_mdk_for_account()` |
| `mdk-core` | Expose crypto provider injection point (if not already available) |
| `whitenoise-linux` | Add KeyMaster login flow in UI, remove vault requirement when KeyMaster is selected |
| `whitenoise` (Flutter) | Add KeyMaster login option (optional, can be deferred) |
| `club.dwdc.keyvault` | Add `Protocol.MLS(1242)`, add role constants for SIGN and HPKE |
| `club.dwdc.keymaster` | Add MLS service handler, MLS identity template |

### KeyMaster Communication

Whitenoise communicates with the KeyMaster using existing Nostr
signing protocols:

| Platform | Transport | Protocol |
|---|---|---|
| Android | Android Intent | NIP-55 |
| Linux / macOS / Windows | Nostr relay | NIP-46 |
| iOS | Nostr relay | NIP-46 |

The KeyMaster already implements both NIP-55 and NIP-46 for Nostr
signing operations. MLS support extends these protocols with
additional methods (see `mls-signer-api.md`).

The user selects an MLS-compatible account inside KeyMaster at
connection time. From that point, the session is scoped to that
account. Whitenoise only knows the Nostr pubkey — all derivation
path resolution (mangle, coin type, algorithm field, device binding)
is internal to KeyMaster.

The KeyMaster process holds the mnemonic in memory. The Whitenoise
process never sees the mnemonic or any private key material — only
public keys and signatures cross the protocol boundary. This is the
same security model as any other NIP-46/NIP-55 external signer.

---

## Summary

The KeyVault derivation schema fits MLS key generation without
structural changes. MLS keys occupy a new branch (`coin_type = 1242`) in
the existing 5-level BIP-32 path alongside Nostr, SSH, GPG, and other
protocols. The Ed25519 and X25519 algorithms required by MLS are already
implemented in the KeyVault.

The user chooses between shared mode (all devices derive the same MLS
identity) and device-bound mode (each device derives a distinct identity
by mixing a hardware ID into the mangle input). The KeyVault does not
distinguish between modes — the choice is encoded entirely in the
identity string.

The primary advantages are single-secret recovery (mnemonic only),
elimination of the encrypted vault, and a unified security boundary
across all protocols. The primary tradeoff is that the mnemonic becomes
a single point of compromise for all derived keys, and HPKE init key
derivation requires a persisted counter.
