# HPKE Welcome Decryption: Current vs Proposed

## What Happens During a Welcome

When Alice invites Bob to a group, she encrypts a `GroupSecrets` payload to
Bob's HPKE init public key (from his published KeyPackage). Bob must decrypt
this to join the group.

The HPKE encryption uses `DHKEM(X25519, HKDF-SHA256)` + `AES-128-GCM`
(RFC 9180). Decryption requires:

```
Inputs:
  kem_output     32 bytes   ephemeral X25519 public key chosen by Alice
  ciphertext     N bytes    AES-128-GCM encrypted GroupSecrets
  init_pub_key   32 bytes   Bob's X25519 public key (from KeyPackage)
  init_priv_key  32 bytes   Bob's X25519 private key (the secret)
  info           variable   serialised label "MLS 1.0 Welcome" + encrypted_group_info
  aad            0 bytes    empty for Welcome

Steps:
  1. DH:        shared_dh   = X25519(init_priv_key, kem_output)
  2. KEM ctx:   kem_context = kem_output || init_pub_key
  3. Extract:   shared_secret = ExtractAndExpand(shared_dh, kem_context)
  4. Key sched: key, nonce   = KeySchedule(shared_secret, info)
  5. Decrypt:   plaintext    = AES-128-GCM.Open(key, nonce, aad, ciphertext)

Output:
  plaintext  →  GroupSecrets (joiner_secret + PSKs)
```

Only step 1 requires the private key. Steps 2–5 are pure computation on
public values + the DH result.

---

## Current Flow (seed exported from vault)

```
                    Keyvault                           OpenMLS
                    ────────                           ───────
KeyPackage
generation:    FN_EXPORT_SEED(hpke_path)
                    │
                    ▼
               raw ed25519 seed
                    │
               SHA-512 + clamp ──────────────► HpkeKeyPair {
                    │                             private: x25519_scalar,
               FN_KEY_AGREEMENT(basepoint)        public:  x25519_pubkey
                    │                           }
                    ▼                                │
               x25519 pubkey                        ▼
                                            KeyPackageBuilder::init_keypair()
                                                    │
                                                    ▼
                                            KeyPackageBundle stored in SQLite
                                            (contains private_init_key bytes)
                                                    │
                                            Published to relay (public part only)

Welcome
decryption:                                 ProcessedWelcome::new_from_welcome()
                                                    │
                                                    ▼
                                            keys_for_welcome()
                                            → loads KeyPackageBundle from SQLite
                                                    │
                                                    ▼
                                            bundle.init_private_key()
                                            → raw x25519 scalar bytes
                                                    │
                                                    ▼
                                            crypto.hpke_open(
                                              config,
                                              ciphertext,    // kem_output + ct
                                              sk_r = scalar, // ◄── PRIVATE KEY
                                              info,
                                              aad
                                            )
                                                    │
                                                    ▼
                                            Steps 1-5 all inside hpke_open()
                                                    │
                                                    ▼
                                            GroupSecrets plaintext
```

**Problem**: The private key leaves the vault at `FN_EXPORT_SEED`. It sits in
memory, gets stored in SQLite, and is passed as raw bytes to `hpke_open()`.

---

## Proposed Flow (private key stays in vault)

```
                    Keyvault                           OpenMLS
                    ────────                           ───────
KeyPackage
generation:    FN_KEY_AGREEMENT(basepoint)
                    │
                    ▼
               x25519 pubkey ──────────────► HpkeKeyPair {
                                                private: EMPTY / zeroed,
                                                public:  x25519_pubkey
                                             }
                                                    │
                                                    ▼
                                            KeyPackageBuilder::init_keypair()
                                                    │
                                                    ▼
                                            KeyPackageBundle stored in SQLite
                                            (private_init_key is empty)
                                                    │
                                            Published to relay (public part only)

Welcome
decryption:                                 ProcessedWelcome::new_from_welcome(
                                              ...,
                                              decryptor: &dyn InitKeyDecryptor
                                            )
                                                    │
                                                    ▼
                                            keys_for_welcome()
                                            → loads KeyPackageBundle
                                            → extracts init PUBLIC key
                                                    │
                                                    ▼
                                            decryptor.hpke_open(
                                              config,
                                              ciphertext,
               ┌────────────────────────────  init_pub_key,  // ◄── PUBLIC KEY
               │                              info,
               │                              aad
               │                            )
               │
               ▼
          find vault index where
          x25519_pubkey_at(i) == init_pub_key
               │
               ▼
          FN_KEY_AGREEMENT(kem_output, path)
               │                                          No private key
               ▼                                          ever leaves
          shared_dh (32 bytes) ─────────────────────┐     the vault
                                                    │
                                              Steps 2-5 locally:
                                              ExtractAndExpand(shared_dh, kem_ctx)
                                              KeySchedule(shared_secret, info)
                                              AES-128-GCM.Open(key, nonce, ct)
                                                    │
                                                    ▼
                                            GroupSecrets plaintext
```

**Key difference**: Only the DH result (a shared secret, not a private key)
leaves the vault. The vault performs `X25519(private, kem_output)` internally
via `FN_KEY_AGREEMENT`. Steps 2–5 use only public values + the DH result.

---

## The `InitKeyDecryptor` Trait

```rust
/// Delegates HPKE init-key decryption to an external key store.
/// The implementor identifies the correct private key by matching
/// the init public key from the KeyPackage.
pub trait InitKeyDecryptor: Send + Sync {
    fn hpke_open(
        &self,
        config: HpkeConfig,          // ciphersuite HPKE params
        ciphertext: &HpkeCiphertext, // { kem_output, ciphertext }
        init_public_key: &[u8],      // which key to use (for vault lookup)
        info: &[u8],                 // serialised EncryptContext
        aad: &[u8],                  // additional authenticated data
    ) -> Result<Vec<u8>, CryptoError>;
}
```

Signature mirrors `OpenMlsCrypto::hpke_open` but takes the **public** key
instead of the private key. The vault implementation does step 1 internally
and steps 2–5 locally.

---

## What the Vault Decryptor Needs to Implement (Steps 2–5)

Given `shared_dh` from `FN_KEY_AGREEMENT` and the public values:

```
// Step 2: KEM context
kem_context = kem_output || init_pub_key          // concatenate (64 bytes)

// Step 3: ExtractAndExpand (HKDF-SHA256)
// suite_id = "KEM" || I2OSP(kem_id, 2)          // "KEM\x00\x20" for DHKEM(X25519)
prk        = HKDF-Extract(salt="", ikm=shared_dh)
// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || "shared_secret" || kem_context
shared_secret = HKDF-Expand(prk, labeled_info, L=32)

// Step 4: Key schedule (HKDF-SHA256)
// mode = 0x00 (Base mode)
// psk_id_hash = LabeledExtract("", "psk_id_hash", "")
// info_hash   = LabeledExtract("", "info_hash", info)
// ks_ctx      = mode || psk_id_hash || info_hash
// secret      = LabeledExtract(shared_secret, "secret", "")  // no PSK in base mode
key   = LabeledExpand(secret, "key",        ks_ctx, Nk=16)
nonce = LabeledExpand(secret, "base_nonce", ks_ctx, Nn=12)

// Step 5: AEAD (AES-128-GCM)
plaintext = AES-128-GCM.Open(key, nonce, aad, ciphertext)
```

All of this uses standard crates (`hkdf`, `sha2`, `aes-gcm`). The vault
only participates in step 1 via `FN_KEY_AGREEMENT`.
