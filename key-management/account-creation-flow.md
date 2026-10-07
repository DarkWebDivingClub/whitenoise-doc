# Account Creation Flow

Status: Draft

This document traces the full account creation and MLS key generation
flow through the Whitenoise stack, identifying every library involved
and the exact integration points where a KeyVault backend would connect.

---

## Repositories

| Repository | Role |
|---|---|
| `whitenoise-rs` | Core library — accounts, signing, key packages, groups, messages |
| `whitenoise-linux` | Desktop client — UI, vault.db (password-encrypted nsec storage) |
| `whitenoise` | Flutter mobile client — UI, Amber/NIP-55 integration |
| `mdk` (Marmot SDK) | MLS protocol layer — wraps OpenMLS with Nostr-specific extensions |
| `club.dwdc.keyvault` | BIP-32 deterministic key derivation engine |
| `club.dwdc.keymaster` | Key management service — identity templates, service handlers |

## Libraries

| Library | Crate | Purpose |
|---|---|---|
| `nostr-sdk` | `nostr-sdk 0.44` | Nostr protocol, `Keys`, `NostrSigner` trait, event building |
| `keyring-core` | `keyring-core 0.7` | OS-native credential storage (macOS Keychain, Linux keyutils, etc.) |
| `openmls` | `openmls` | MLS protocol implementation (RFC 9420) |
| `openmls_rust_crypto` | `openmls_rust_crypto` | Default OpenMLS crypto backend (`RustCrypto`) |
| `mdk-core` | `mdk-core 0.7.1` | Marmot MLS operations — groups, messages, key packages, welcomes |
| `mdk-sqlite-storage` | `mdk-sqlite-storage 0.7.1` | SQLCipher-encrypted MLS state storage |
| `mdk-storage-traits` | `mdk-storage-traits 0.7.1` | `MdkStorageProvider` trait |
| `sqlx` | `sqlx` (SQLite) | Application database — accounts, users, relays, metadata |
| `chacha20poly1305` | `chacha20poly1305 0.10` | Vault encryption (whitenoise-linux only) |
| `argon2` | `argon2 0.5` | Vault KDF (whitenoise-linux only) |

---

## Current Flow: Local Account Creation

### Step 1 — Generate or Import Keys

```
Account::new(whitenoise, keys: Option<Keys>)
  Location: whitenoise-rs/src/whitenoise/accounts/mod.rs:272

  keys = keys.unwrap_or_else(Keys::generate)
    │
    ├─ Keys::generate()                     ← nostr-sdk
    │    Generates a random secp256k1 keypair.
    │    The secret key is a 32-byte scalar.
    │    The public key is a 32-byte x-only Schnorr key (npub).
    │
    └─ Or: caller provides Keys parsed from nsec (login flow)

  User::find_or_create_by_pubkey()          ← sqlx (app SQLite DB)
    Creates a User record if one does not exist for this pubkey.

  Returns: (Account { pubkey, account_type: Local, ... }, Keys)
```

### Step 2 — Store Nostr Secret Key

```
create_base_account_with_private_key(whitenoise, keys)
  Location: whitenoise-rs/src/whitenoise/accounts/login.rs

  whitenoise.secrets_store.store_private_key(&keys)
    │
    └─ SecretsStore                         ← keyring-core
         Platform-specific credential storage:
           macOS:   Keychain
           iOS:     Protected keystore
           Linux:   keyutils / pass
           Android: Android native keyring
           Windows: Windows native keyring

         Stores: nsec indexed by pubkey hex string.
         The secret key is held in the OS credential store,
         not in the application database.

  whitenoise.persist_account(&account)      ← sqlx
    INSERT INTO accounts (pubkey, user_id, account_type, ...)
```

### Step 3 — Activate Account

```
activate_account(whitenoise, account)
  Location: whitenoise-rs/src/whitenoise/accounts/setup.rs

  ├─ setup_subscriptions(account, inbox_relays)
  │    Subscribes to Nostr relay events:
  │      kind 1059 (gift-wrapped messages)
  │      kind 445  (group messages)
  │      kind 30443 (key packages)
  │
  └─ setup_key_package(account, key_package_relays)
       Creates and publishes the initial MLS key package.
       This is where MLS keys are generated. See Step 4.
```

### Step 4 — Create MDK Instance

```
create_mdk_for_account(pubkey)
  Location: whitenoise-rs/src/whitenoise/mod.rs:394
    → Account::create_mdk(pubkey, data_dir, keyring_service_id)
      Location: whitenoise-rs/src/whitenoise/accounts/mod.rs:555

  MdkSqliteStorage::new(mls_storage_dir, keyring_service_id, db_key_id)
    │                                                        ← mdk-sqlite-storage
    │
    │  mls_storage_dir = $DATA_DIR/mls/<pubkey_hex>/
    │  db_key_id       = "mdk.db.key.<pubkey_hex>"
    │
    │  The SQLCipher database encryption key is stored in the
    │  platform keyring (same keyring-core backend as the nsec).
    │  The database file itself is AES-256-CBC encrypted at rest.
    │
    └─ Contains: MLS group state, ratchet trees, epoch secrets,
                 signing private keys, HPKE private keys,
                 key package hash refs, pending commits.

  MDK::new(storage)
    Location: mdk-core/src/lib.rs:383
      → MdkBuilder::new(storage).build()
        Location: mdk-core/src/lib.rs:247

    MdkProvider {
        crypto: RustCrypto::default(),          ← openmls_rust_crypto
        storage: storage,                       ← mdk-sqlite-storage
    }

    ┌─────────────────────────────────────────────────────┐
    │  RustCrypto is hardcoded here.                      │
    │                                                     │
    │  It provides:                                       │
    │    CryptoProvider  — Ed25519, X25519, AES-GCM,      │
    │                      HKDF-SHA256, SHA-256            │
    │    RandProvider    — CSPRNG (OS random)              │
    │                                                     │
    │  All MLS key generation flows through RustCrypto.   │
    │  There is no injection point for an alternative     │
    │  crypto backend.                                    │
    │                                                     │
    │  THIS IS THE INTEGRATION BOTTLENECK FOR KEYVAULT.   │
    └─────────────────────────────────────────────────────┘
```

### Step 5 — Generate MLS Key Package

```
mdk.create_key_package_for_event(&pubkey, relay_urls)
  Location: mdk-core/src/key_packages.rs

  Internally calls OpenMLS KeyPackage::builder() which uses the
  MdkProvider to:

  1. Generate Ed25519 signing keypair          ← RustCrypto (random)
       This is the MLS leaf signing key.
       Private key stored in MdkSqliteStorage (SQLCipher).
       Public key embedded in the KeyPackage leaf node.

  2. Generate X25519 HPKE init keypair         ← RustCrypto (random)
       This is the KeyPackage init key for Welcome decryption.
       Private key stored in MdkSqliteStorage (SQLCipher).
       Public key embedded in the KeyPackage.

  3. Build AccountIdentityProof extension
       Binds the Nostr npub to the Ed25519 MLS signing key.
       The proof itself is computed by mdk-core, but the
       BIP-340 Schnorr signature is produced outside of MDK.
       (The current implementation pre-computes it before
       passing to create_key_package_for_event.)

  4. Serialize KeyPackage to TLS wire format, base64 encode.

  Returns: (encoded_content: String, tags: Vec<Tag>, hash_ref: Vec<u8>)
```

### Step 6 — Publish Key Package to Nostr Relays

```
publish_key_package_to_relays(encoded, relay_urls, tags, signer)
  Location: whitenoise-rs/src/whitenoise/key_packages.rs:425

  signer = get_signer_for_account(account)
    │
    ├─ Check external_signers DashMap first      ← DashMap<PublicKey, Arc<dyn NostrSigner>>
    │    If found: use external signer (Amber, KeyVault, etc.)
    │
    └─ Fallback: secrets_store.get_nostr_keys_for_pubkey()
         Load Keys from platform keyring         ← keyring-core
         Keys implements NostrSigner.

  Build Nostr event:
    kind:    30443 (MLS Key Package, replaceable)
    content: base64-encoded KeyPackage
    tags:    mls_ciphersuite, mls_extensions, encoding, relay hints
    signed:  BIP-340 Schnorr signature           ← NostrSigner

  Publish to key package relays.
```

---

## Current Flow: External Signer Account Creation

```
Account::new_external(whitenoise, pubkey)
  Location: whitenoise-rs/src/whitenoise/accounts/mod.rs:296

  Takes only a pubkey. No secret key touches the application.

  User::find_or_create_by_pubkey()              ← sqlx
  Returns: Account { pubkey, account_type: External, ... }

  ┌──────────────────────────────────────────────────────┐
  │  No key is stored in secrets_store.                  │
  │  The secret key lives in the external signer         │
  │  (e.g., Amber on Android via NIP-55).                │
  │                                                      │
  │  The signer is registered at runtime:                │
  │    whitenoise.register_external_signer(pubkey, s)    │
  │    → validates signer pubkey matches                 │
  │    → inserts into external_signers DashMap            │
  │                                                      │
  │  From this point, get_signer_for_account() returns   │
  │  the registered external signer for all Nostr        │
  │  operations.                                         │
  │                                                      │
  │  MLS key generation is UNCHANGED — RustCrypto still  │
  │  generates MLS keys randomly inside MDK. The         │
  │  external signer is only used for Nostr event        │
  │  signing (kind-30443 publication, kind-1059           │
  │  gift wraps, etc.).                                  │
  └──────────────────────────────────────────────────────┘
```

---

## Proposed Flow: KeyVault Account Creation

### Step 1 — Connect to KeyMaster

```
Whitenoise connects to KeyMaster using the platform signing protocol:
  Android:  NIP-55 (Intent)
  Desktop:  NIP-46 (Nostr relay)

The user selects an MLS-compatible account inside KeyMaster.
KeyMaster returns the Nostr pubkey for that account.

  No mnemonic, nsec, or private key material enters the
  Whitenoise process. All derivation path resolution (mangle,
  coin type, identity string, device binding) is internal to
  KeyMaster. Whitenoise only sees the pubkey.
```

### Step 2 — Get Nostr Public Key

```
  NIP-46 request:
    { "method": "get_public_key", "params": [] }

  NIP-46 response:
    { "result": "<32-byte-hex-npub>" }

  KeyMaster internally derives at:
    m / 44' / 1237' / mangle("alice@atlanta.com")' / SCHNORR|0|0' / 0|0'

  Whitenoise receives only the public key. It does not know the
  identity string, the mangle value, or the derivation path.
```

### Step 3 — Register as External Signer

```
  The NIP-46 connection (or NIP-55 signer) is registered as an
  external signer in the existing DashMap:

  whitenoise.insert_external_signer(nostr_pubkey, nip46_signer)
    │
    └─ Registers in the same DashMap used by Amber/NIP-55.
       get_signer_for_account() will return this signer.

  Nostr signing operations (sign_event, nip44_encrypt, etc.)
  flow through the standard NIP-46/NIP-55 methods. No changes
  to whitenoise-rs signing infrastructure.

  ┌──────────────────────────────────────────────────────┐
  │  No changes to AccountType needed.                   │
  │  The KeyMaster looks like any other external signer  │
  │  to whitenoise-rs.                                   │
  │                                                      │
  │  Account is AccountType::External (pubkey only,      │
  │  no nsec stored). The UI may optionally distinguish  │
  │  KeyMaster from Amber via the signer metadata.       │
  └──────────────────────────────────────────────────────┘
```

### Step 4 — Create Account

```
  Account::new_external(whitenoise, nostr_pubkey)
    Same as current external flow.
    User record created, account persisted to DB.
    No secret key stored in secrets_store or vault.db.
```

### Step 5 — Create MDK with Pluggable Crypto (requires mdk-core fork)

```
  create_mdk_for_account(pubkey)
    → Account::create_mdk(pubkey, data_dir, keyring_service_id,
                          keyvault_crypto)         ← NEW PARAMETER

  MdkSqliteStorage::new(...)                       ← unchanged

  MDK::builder(storage)
      .with_crypto(keyvault_crypto)                ← NEW BUILDER METHOD
      .build()

  MdkProvider {
      crypto: keyvault_crypto,                     ← KeyVaultCryptoProvider
      storage: storage,
  }

  ┌──────────────────────────────────────────────────────┐
  │  REQUIRED CHANGE IN mdk-core:                        │
  │                                                      │
  │  Current (hardcoded):                                │
  │    pub struct MdkProvider<Storage> {                  │
  │        crypto: RustCrypto,                           │
  │        storage: Storage,                             │
  │    }                                                 │
  │                                                      │
  │  Proposed (generic):                                 │
  │    pub struct MdkProvider<Crypto, Storage> {          │
  │        crypto: Crypto,                               │
  │        storage: Storage,                             │
  │    }                                                 │
  │                                                      │
  │  Where Crypto: OpenMlsCryptoProvider + OpenMlsRand   │
  │                                                      │
  │  Default construction (MDK::new) still uses          │
  │  RustCrypto. Existing code is unaffected.            │
  └──────────────────────────────────────────────────────┘
```

### Step 6 — Generate MLS Key Package via KeyMaster

```
  mdk.create_key_package_for_event(&pubkey, relay_urls)

  KeyMasterCryptoProvider intercepts the key generation calls
  from OpenMLS and delegates via NIP-46/NIP-55 MLS extensions:

  Ed25519 signing keypair:
    ├─ Public key:
    │    NIP-46: { "method": "mls_get_signing_key", "params": [] }
    │    → "<hex-ed25519-pubkey>"
    │
    │    KeyMaster internally derives at:
    │    m / 44' / 1242' / mangle(identity)' / ED25519|0|SIGN' / 0|0'
    │
    └─ Signing:
         NIP-46: { "method": "mls_sign", "params": ["<hex-data>"] }
         → "<hex-ed25519-signature>"

         Private key never leaves the KeyMaster process.

  X25519 HPKE init keypair:
    ├─ Public key:
    │    NIP-46: { "method": "mls_get_hpke_init_key", "params": ["3"] }
    │    → "<hex-x25519-pubkey>"
    │
    │    KeyMaster internally derives at:
    │    m / 44' / 1242' / mangle(identity)' / ED25519|0|HPKE' / 0|3'
    │    KeyMaster manages the index counter internally.
    │
    └─ Decapsulation (Welcome processing):
         NIP-46: { "method": "mls_hpke_decap",
                    "params": ["3", "<hex-kem-output>"] }
         → "<hex-dh-shared-secret>"

         KeyMaster performs X25519(sk, kem_output) and returns the
         raw DH result. The HPKE ExtractAndExpand (HKDF) step is
         performed locally by the crypto provider — it uses only
         public data and the DH result, no private key involved.

  Symmetric operations (AES-128-GCM, HKDF-SHA256, SHA-256):
    └─ Passed through to RustCrypto default implementation.
       No KeyMaster involvement. These use ephemeral keys
       from the MLS key schedule, not derived from the seed.

  Random number generation:
    └─ Passed through to RustCrypto (OS CSPRNG).
       Used for MLS nonces, GREASE values, etc.
       Not related to identity key derivation.
```

### Step 7 — Publish Key Package (Unchanged)

```
  publish_key_package_to_relays(encoded, relay_urls, tags, signer)

  signer = get_signer_for_account(account)
    → Returns the NIP-46/NIP-55 signer from step 3.

  Event signed by BIP-340 Schnorr via NIP-46:
    { "method": "sign_event", "params": ["<unsigned-event-json>"] }

  Published to relays as kind-30443. Identical wire format.
  Other clients cannot distinguish a KeyMaster-signed event
  from a locally-signed one.
```

---

## KeyVaultCryptoProvider: Delegation Boundary

The `KeyVaultCryptoProvider` wraps `RustCrypto` and overrides only the
asymmetric key operations. Everything else passes through unchanged.

```
┌─────────────────────────────────────────────────────────────┐
│                   KeyVaultCryptoProvider                     │
│                                                             │
│  Delegated to KeyVault:              Passed to RustCrypto:  │
│  ─────────────────────               ────────────────────── │
│  Ed25519 keypair generation          AES-128-GCM encrypt    │
│  Ed25519 sign                        AES-128-GCM decrypt    │
│  Ed25519 verify (optional*)          HKDF-SHA256 extract    │
│  X25519 keypair generation           HKDF-SHA256 expand     │
│  X25519 derive (ECDH / HPKE)        SHA-256 hash           │
│                                      HPKE encapsulate**     │
│                                      Random bytes (CSPRNG)  │
│                                                             │
│  * Verify can stay in RustCrypto — it uses public keys only │
│  ** Encapsulate uses the recipient's public key, no local   │
│     private key involved                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## MLS Key Storage: What Changes

### Current (RustCrypto + SQLCipher)

```
MLS private keys (Ed25519 signing, X25519 HPKE init):
  Generated randomly by RustCrypto
  Stored in SQLCipher DB ($DATA_DIR/mls/<pubkey>/db.sqlite)
  DB encryption key stored in platform keyring (keyring-core)
  Must be backed up to recover MLS state on a new device
```

### With KeyVault

```
MLS private keys (Ed25519 signing, X25519 HPKE init):
  Derived deterministically by KeyVault from mnemonic + path
  NEVER stored in SQLCipher DB — re-derived on each use
  No DB encryption key needed for private key material
  Recovery requires only the mnemonic

SQLCipher DB still needed for:
  MLS group state (epoch, ratchet tree, group context)
  Pending commits and proposals
  Message queues and epoch snapshots
  Key package hash refs for lifecycle tracking
  Per-sender ratchet state

These are ephemeral MLS protocol state, not identity keys.
They cannot be derived from the mnemonic. They must still be
stored and backed up for session continuity.
```

---

## HPKE Init Key Index Recovery

When a device starts fresh (new device or after wipe), it needs to
know which HPKE init key indices have already been used:

```
Recovery flow:
  1. Derive Nostr pubkey from mnemonic
       m / 44' / 1237' / mangle(identity)' / SCHNORR|0|0' / 0|0'

  2. Query relays for published key packages
       Filter: kind=30443, author=<nostr_pubkey>

  3. For each published KeyPackage event:
       Parse KeyPackage, extract HPKE init public key (X25519)

  4. Scan derivation indices:
       for N in 0.. {
           candidate = keyvault.execute(FN_GET_PUBLIC_KEY, &[],
               &[44, 1242, mangle(identity), ed25519|0|HPKE, 0|N])
           if candidate matches a published init key:
               record N as used
           if N > highest_match + gap_threshold:
               break
       }

  5. Resume from max(used_indices) + 1

  The scan is fast: one HKDF + one X25519 scalar-base-multiply per
  candidate. Typical search space is tens of KeyPackages.
```

---

## Component Dependency Map

```
                        ┌──────────────┐
                        │   User (UI)  │
                        └──────┬───────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐  ┌─────▼──────┐  ┌──────▼───────┐
     │ whitenoise-   │  │ whitenoise │  │ whitenoise   │
     │ linux (Slint) │  │ (Flutter)  │  │ (future CLI) │
     └────────┬──────┘  └─────┬──────┘  └──────┬───────┘
              │               │                │
              └───────────────┼────────────────┘
                              │
                     ┌────────▼────────┐
                     │  whitenoise-rs  │
                     │  (core library) │
                     └───┬────────┬───┘
                         │        │
            ┌────────────┘        └────────────────┐
            │                                      │
   ┌────────▼────────┐                    ┌────────▼────────┐
   │  Nostr Signing   │                    │  MLS Protocol   │
   │                  │                    │                  │
   │  NostrSigner     │                    │  mdk-core        │
   │  (trait)         │                    │  └─ OpenMLS      │
   │                  │                    │                  │
   │  Backends:       │                    │  CryptoProvider: │
   │  ├─ Keys         │                    │  ├─ RustCrypto   │
   │  │  (local nsec) │                    │  │  (current)    │
   │  ├─ Amber        │                    │  └─ KeyVault     │
   │  │  (NIP-55)     │                    │     (proposed)   │
   │  └─ KeyVault     │                    │                  │
   │     (proposed)   │                    │  Storage:        │
   │                  │                    │  └─ SQLCipher     │
   └──────────────────┘                    └──────────────────┘
            │                                      │
            │  ┌───────────────────────────────┐   │
            └──┤  KeyMaster / KeyVault         ├───┘
               │                               │
               │  Mnemonic → BIP-32 derivation │
               │                               │
               │  Nostr:  m/44'/1237'/...      │
               │  MLS:    m/44'/1242'/...      │
               │  SSH:    m/44'/1238'/...      │
               │  GPG:    m/44'/1239'/...      │
               │                               │
               │  NIP-55 (Android Intent)      │
               │  NIP-46 (Nostr relay)         │
               └───────────────────────────────┘
```

---

## Required Changes by Repository

### mdk (Marmot SDK) — Fork Required

| File | Change |
|---|---|
| `mdk-core/src/lib.rs` | Make `MdkProvider` generic over `Crypto` type parameter. Add `with_crypto()` to `MdkBuilder`. Default construction still uses `RustCrypto`. |
| `mdk-core/src/key_packages.rs` | No changes — calls go through `OpenMlsProvider` trait which becomes generic. |
| `mdk-core/src/groups.rs` | No changes — same reason. |
| `mdk-core/src/messages/` | No changes — same reason. |

The change is in the type signature of `MdkProvider` and `MDK`.
All call sites already use the `OpenMlsProvider` trait, so they
work with any backend that implements the trait.

### whitenoise-rs — Core Library

| File | Change |
|---|---|
| `accounts/mod.rs` | `create_mdk()` accepts optional crypto provider parameter. |
| `signer.rs` | No changes — KeyMaster registers as external signer via existing NIP-46/NIP-55 path. |
| New: `keymaster_crypto.rs` | `OpenMlsCryptoProvider` implementation that delegates asymmetric ops to KeyMaster via NIP-46 MLS extension methods, passes symmetric ops to `RustCrypto`. |

### whitenoise-linux — Desktop Client

| File | Change |
|---|---|
| `main.rs` / login flow | Add KeyMaster login option (mnemonic-based). |
| `vault.rs` | Unchanged — still available for users who prefer password-based vault. |

### club.dwdc.keyvault — Key Derivation Engine

| File | Change |
|---|---|
| `Protocol.java` | Add `MLS(1242)`. |

No other changes — the KeyVault already implements Ed25519 and X25519.

### club.dwdc.keymaster — Key Management Service

| File | Change |
|---|---|
| `KeyMasterController.java` | Add MLS identity creation to `createIdentity()`. |
| New: MLS service handler | Handles MLS-specific key entry metadata (HPKE index tracking). |
| Identity templates | Add `mls-shared` and `mls-device-bound` templates. |

---

## Summary: What Goes Where

```
KeyVault:       Derives keys. Knows nothing about MLS or Nostr.
                Pure function: (operation, payload, path) → bytes.

KeyMaster:      Manages identities and paths. Knows protocols.
                Maps "alice@atlanta.com" + "MLS" → derivation path.
                Tracks HPKE init key counter.

whitenoise-rs:  Core app logic. Talks to KeyMaster via NIP-46/NIP-55.
                Nostr signing uses standard NIP-46 methods.
                MLS crypto uses NIP-46 MLS extension methods.
                Does not know about derivation paths, mangle, or
                identity strings.

mdk-core:       MLS protocol engine. Accepts pluggable crypto.
                Does not know about KeyVault, mnemonic, or BIP-32.
                Just calls CryptoProvider trait methods.

OpenMLS:        RFC 9420 implementation. Calls CryptoProvider.
                Completely unaware of key source.
```
