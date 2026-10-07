# Group Creation Example: HD Seed Version

A concrete walkthrough of how four people create an encrypted group chat
using Whitenoise with KeyMaster/KeyVault HD seed derivation instead of
imported nsecs and encrypted vaults.

Compare with `group-creation-example.md` for the current nsec-based flow.

## Step 1 — Alice Creates an Identity in KeyMaster

Alice has a KeyMaster with a BIP-39 mnemonic. She creates an identity:

```
1a. Alice creates identity "alice@atlanta.com" in KeyMaster

    KeyMaster internally derives all key branches for this identity:
      Nostr:  m/44'/1237'/mangle("alice@atlanta.com")'/SCHNORR|0|0'/0|0'
              -> alice_npub (secp256k1 x-only public key)
      MLS:    m/44'/1242'/mangle("alice@atlanta.com")'/ED25519|0|SIGN'/0|0'
              -> alice_ed25519.pub (Ed25519 public key)

    This happens entirely inside KeyMaster. Whitenoise is not involved yet.
```

---

## Step 2 — Alice Connects Whitenoise to KeyMaster

Alice opens Whitenoise and attaches her KeyMaster account.

```
2a. Alice initiates connect from Whitenoise:
    connect() -> KeyMaster
    (transport: NIP-46 relay-based, NIP-55 Android intent, etc.)

2b. Alice selects "alice@atlanta.com" inside KeyMaster

2c. KeyMaster returns: alice_npub (Nostr public key)
    This is the account identifier. Whitenoise now knows who Alice is.

2d. Account created in Whitenoise:
    AccountType::KeyMaster
    pubkey: alice_npub
    No vault.db, no password, no keyring entry for nsec

    The Nostr pubkey serves as the account selector — it uniquely
    identifies the account across Whitenoise and KeyMaster.
```

---

## Step 3 — Alice Sets Up MLS

Whitenoise needs MLS capability for this account. It calls
`get_mls_pubkey` to get the MLS signing key.

```
3a. Get MLS public key — get_mls_pubkey(null, "0x0001"):
    - device_id = null (Alice wants shared mode)
    - ciphersuite = "0x0001" (Ed25519 + X25519)

    KeyMaster returns: alice_ed25519.pub (Ed25519 public key)

    Internally, KeyMaster resolved:
      identity = "alice@atlanta.com"  (from the account selected in step 2)
      device_id = null, so no device mixing
      mangle("alice@atlanta.com") = 0x748b0a69
      sign_path = m/44'/1242'/748b0a69'/ED25519|0|SIGN'/0|0'
      hpke_path = m/44'/1242'/748b0a69'/ED25519|0|HPKE'/0|{index}'

    Whitenoise knows none of this. It only sees the public key.

3b. Client reads current HPKE state from relay:
    Query kind-30443 where pubkey = alice_npub
    No KeyPackage found (new account) -> current_hpke_pubkey = null

3c. Client configures CryptoProvider:
    KeyMasterCryptoProvider {
      signer: <KeyMaster connection>,
      signing_key: alice_ed25519.pub,     <- from get_mls_pubkey
      current_hpke_pubkey: null,           <- from relay (none yet)
      default_crypto: RustCrypto,
    }

3d. AccountIdentityProof — bind Nostr identity to MLS key:
    canonical = "marmot.account-identity-proof.v1" || 0x00 || 0xF2F1 || 0x01
              || 0x0001 || sig_scheme
              || len(alice_npub) || alice_npub
              || len(alice_ed25519.pub) || alice_ed25519.pub
    digest = SHA-256(canonical)

    Client sends digest to KeyMaster for Nostr signing:
    proof_sig = KeyMaster.sign(digest)   <- BIP-340 Schnorr, via Nostr path

    This proof says: "I, alice_npub (secp256k1), authorize alice_ed25519.pub
                      as my MLS signing key"

    Both keys are derived from the same mnemonic, from different branches:
      Nostr:  m/44'/1237'/748b0a69'/...  -> alice_npub
      MLS:    m/44'/1242'/748b0a69'/...  -> alice_ed25519.pub
```

At this point Alice has:

- Nostr identity: `alice_npub` (secp256k1, derived from mnemonic)
- MLS identity: `alice_ed25519.pub` (Ed25519, derived from mnemonic)
- A cryptographic proof binding the two
- No private keys on the client device

---

## Step 4 — Alice Publishes a KeyPackage

Alice's app requests the first HPKE init key and builds a KeyPackage:

```
4a. Get first HPKE init key:
    Client calls: mls_next_hpke_init_key(null)   <- null = no prior key
    KeyMaster derives: m/44'/1242'/748b0a69'/ED25519|0|HPKE'/0|0'
    Returns: alice_x25519_0.pub (X25519 public key)

    The client stores alice_x25519_0.pub as the HPKE "private key" handle
    in OpenMLS storage. OpenMLS thinks it has a private key; the client
    knows it's just a public key handle that the CryptoProvider will use
    to call back to KeyMaster for decapsulation.

4b. KeyPackage built:
    KeyPackage {
      init_key: alice_x25519_0.pub,
      leaf_node: {
        signature_key: alice_ed25519.pub,
        credential: BasicCredential(alice_npub),
        extensions: [
          AccountIdentityProof { alice_npub, alice_ed25519.pub, proof_sig },
          AppComponents { ... }
        ]
      }
      signed by: alice_ed25519   <- Client sends TLS-serialized content to
                                    KeyMaster via mls_sign(data), gets back
                                    the Ed25519 signature
    }

4c. Published to relays as Nostr event:
    kind:    30443
    pubkey:  alice_npub
    content: base64(MLS-serialize(KeyPackage))
    tags:    [["d", random_slot_hex], ["mls_ciphersuite", "0x0001"], ...]
    sig:     KeyMaster.sign(event_id)   <- BIP-340 Schnorr, via Nostr path
```

Two different key types sign two different things, both via KeyMaster:

- `alice_ed25519` signs the MLS KeyPackage (MLS layer, via `mls_sign`)
- `alice_npub` key signs the Nostr event (transport layer, via Nostr signer)

---

## Step 5 — Bob, Carol, David Do the Same

Each person creates an identity in their KeyMaster, connects it to
Whitenoise (steps 1-3), and publishes a KeyPackage (step 4):

```
Bob:
  1. Creates identity "bob@boston.com" in his KeyMaster
  2. connect() from Whitenoise -> KeyMaster returns bob_npub
  3. get_mls_pubkey(null, "0x0001") -> bob_ed25519.pub
  4. mls_next_hpke_init_key(null) -> bob_x25519_0.pub
     AccountIdentityProof(bob_npub <-> bob_ed25519.pub)
     KeyPackage published (kind 30443)

Carol:
  1-4. Same flow with identity "carol@chicago.com"
       carol_npub, carol_ed25519.pub, carol_x25519_0.pub

David:
  1-4. Same flow with identity "david@denver.com"
       david_npub, david_ed25519.pub, david_x25519_0.pub
```

---

## Step 6 — Alice Creates the MLS Group

Alice decides to create a group:

```
MLS Group created locally:
  group_id:    random 32 bytes
  ciphersuite: 0x0001 (X25519 / AES-128-GCM / SHA-256 / Ed25519)
  epoch:       0
  tree:        [ Alice_leaf ]

Epoch 0 secrets derived:
  group_event_key = MLS-Exporter("marmot", "group-event", 32)
```

Nothing published yet. Alice is the only member.

---

## Step 7 — Alice Fetches KeyPackages from Relays

```
Alice queries relays:
  GET kind:30443 where pubkey IN [bob_npub, carol_npub, david_npub]

For each KeyPackage received, the engine validates:
  1. Credential identity (32 bytes) is a valid secp256k1 x-only point
  2. Extension 0xF2F1 present
  3. Proof's account_identity matches credential
  4. Proof's mls_signature_public_key matches leaf signature key
  5. BIP-340 Schnorr verify(npub, SHA-256(canonical), proof_sig)
  6. Ciphersuite is 0x0001
```

This step is identical to the nsec-based flow. The verifier does not
know or care whether the signer used a random key or an HD-derived key.

---

## Step 8 — Alice Commits the Adds (Epoch Transition)

### The Commit

Alice's engine stages a commit with three Add proposals:

```
8a. Stage the commit:

    mls_group.add_members([Bob_KP, Carol_KP, David_KP])
      -> produces: StagedCommit + MLS Welcome messages (one per invitee)

    The commit contains:
      - Proposal: Add(Bob's KeyPackage)
      - Proposal: Add(Carol's KeyPackage)
      - Proposal: Add(David's KeyPackage)
      - UpdatePath: Alice's new path keys

    Signed by: alice_ed25519 (via mls_sign -> KeyMaster)

    Engine transitions: Stable{epoch:0} -> PendingPublish{epoch:1}
```

### The UpdatePath — Alice's Key Rotation

Every commit includes an UpdatePath. The CryptoProvider generates new
HPKE keys for Alice's leaf and direct path nodes:

```
8b. UpdatePath generation:

    Alice's leaf needs a new HPKE key:
      CryptoProvider calls mls_next_hpke_init_key(alice_x25519_0.pub)
      KeyMaster finds index 0 matches, derives index 1:
        m/44'/1242'/748b0a69'/ED25519|0|HPKE'/0|1'
      Returns: alice_x25519_1.pub

    New ratchet tree (epoch 1):

              [root]              <- new HPKE key from path_secret[root]
             /      \
        [node]      [node]        <- new HPKE keys from path_secret[nodes]
        /    \      /    \
    Alice   Bob  Carol  David

    Alice's leaf:
      +-- NEW HPKE key:     alice_x25519_1.pub  (derived from HD seed)
      +-- Signature key:    alice_ed25519.pub    (unchanged, same path)
      +-- Credential:       BasicCredential(alice_npub)

    Path secrets encrypted to co-path nodes as usual.
    Bob, Carol, David each receive their path secrets via HPKE.

    All MLS signatures in this commit go through:
      Client -> mls_sign(data) -> KeyMaster -> Ed25519 signature
```

### Publish-Before-Apply

```
8c. State machine transitions:

    Stable{epoch:0}
        |
        | Alice stages the commit
        v
    PendingPublish{epoch:1}
        |
        |--- on transport success ---> Merging ---> Stable{epoch:1}
        |
        |--- on transport failure ---> Stable{epoch:0}
                                       (staged state discarded)
```

---

## Step 9 — Alice Publishes the Commit (Kind 445)

```
MLS commit bytes
    |
ChaCha20-Poly1305:
    key   = epoch 0 group_event_key (only Alice has this)
    nonce = random(12)
    ct    = encrypt(key, nonce, mls_commit_bytes)
    |
Nostr kind-445 event:
    pubkey:  eph_1.pub           <- fresh secp256k1 keypair, locally generated
    content: base64(nonce || ct)
    tags:    [["h", transport_group_id]]
    sig:     BIP-340_Sign(eph_1.sec, event_id)  <- ephemeral, NOT from KeyMaster

-> relays
```

Note: Ephemeral keys for kind-445 events are still randomly generated
locally. They are throwaway keys used once and discarded — there is no
benefit to deriving them from the HD seed.

---

## Step 10 — Alice Sends Welcomes via NIP-59

For each of Bob, Carol, David, Alice wraps a Welcome in NIP-59 layers.
Here is Bob's:

```
--- Inner: MLS Welcome ---
  Encrypted TO bob_x25519_0.pub (from Bob's KeyPackage)
  Contains: epoch 1 ratchet tree, key schedule, member list
  Only Bob's KeyMaster can decapsulate this (via mls_hpke_decap)

--- Rumor (kind 444, unsigned) ---
  pubkey:  alice_npub
  content: base64(MLS Welcome bytes)
  tags:    [["e", bob_keypackage_event_id],
            ["relays", "wss://relay1", ...]]

--- Seal (kind 13) ---
  NIP-44 ECDH: KeyMaster computes shared secret via Nostr key agreement
  content: NIP-44_Encrypt(rumor, shared_secret)
  signed by: alice_npub key (via KeyMaster)

--- Gift Wrap (kind 1059) ---
  NIP-44 ECDH: ecdh(eph_2.sec, bob_npub)   <- ephemeral, local
  content: NIP-44_Encrypt(seal, shared_secret)
  pubkey:  eph_2.pub
  tags:    [["p", bob_npub]]
  signed by: eph_2.sec   <- ephemeral, local

-> Published to Bob's inbox relays (kind 10050)
```

---

## Step 11 — Bob Receives the Welcome

```
Bob sees kind 1059 addressed to bob_npub on his inbox relay

11a. Unwrap gift wrap:
    KeyMaster.nip44_decrypt(gift_wrap.pubkey, gift_wrap.content)
    -> returns plaintext JSON: a kind-13 Seal event
       { pubkey: alice_npub, content: <nip44 ciphertext>, ... }

11b. Unwrap seal:
    KeyMaster.nip44_decrypt(seal.pubkey, seal.content)
    -> returns plaintext JSON: a kind-444 Rumor (unsigned event)
       { pubkey: alice_npub, content: base64(MLS Welcome bytes), ... }
    -> Bob now knows Alice sent the invite

11c. Decode MLS Welcome:
    welcome_bytes = base64_decode(rumor.content)

11d. Process MLS Welcome:
    Bob passes welcome_bytes to OpenMLS:
      mls_group = MlsGroup::new_from_welcome(welcome_bytes)

    Inside OpenMLS, this triggers a chain of operations:

    1. Parse Welcome structure:
       The Welcome contains:
         - EncryptedGroupSecrets (one per invitee, keyed by KeyPackage hash)
         - The group's ratchet tree and GroupInfo (encrypted)

       OpenMLS finds the EncryptedGroupSecrets entry that matches
       Bob's KeyPackage hash.

    2. HPKE decapsulation (KeyMaster call):
       The EncryptedGroupSecrets contains a kem_output — the sender's
       ephemeral X25519 public key used to encrypt the group secrets
       to Bob's HPKE init key.

       OpenMLS calls hpke_open() on the CryptoProvider with:
         - the "private key" (which is actually bob_x25519_0.pub,
           the handle stored when the KeyPackage was created)
         - the kem_output from the Welcome
         - the HPKE ciphertext containing the encrypted joiner_secret

       Bob's CryptoProvider splits this into two steps:

       a) Remote DH via KeyMaster:
          dh_result = KeyMaster.mls_hpke_decap(bob_x25519_0.pub, kem_output)

          KeyMaster internally:
            - Derives HPKE keys at index 0, 1, 2... until the public
              key matches bob_x25519_0.pub (finds index 0)
            - Performs X25519(sk_init[0], kem_output)
            - Returns: dh_result (32 bytes, raw X25519 output)

       b) Local HKDF (no KeyMaster needed):
          kem_context = kem_output || bob_x25519_0.pub
          hpke_shared_secret = ExtractAndExpand(dh_result, kem_context)

       c) Local AEAD decrypt (no KeyMaster needed):
          Use hpke_shared_secret to derive an AES-128-GCM key
          Decrypt the HPKE ciphertext -> joiner_secret

    3. Derive epoch 1 key schedule (all local, no KeyMaster):
       The joiner_secret feeds into the MLS key schedule:

         joiner_secret + psk_secret
             |
             v
         epoch_secret[1]
             |
             +-- encryption_secret -> per-sender AES-128-GCM keys
             +-- exporter_secret   -> group_event_key, media_secret, ...
             +-- confirmation_key, membership_key, ...
             +-- init_secret[1]    -> feeds next epoch

    4. Decrypt and install ratchet tree (all local):
       Using keys from the epoch schedule, OpenMLS decrypts the
       GroupInfo, validates the ratchet tree, and installs it.

       Bob now has the full tree with all members' public keys
       and can verify their AccountIdentityProofs.

    After this step Bob has:
    -> Full ratchet tree with 4 leaves
    -> Epoch 1 key schedule (all symmetric keys)
    -> group_event_key for decrypting kind-445 events
    -> Per-sender ratchets for all 4 members
    -> Bob can now send and receive messages in this group

11e. Bob sees the member list:
    Leaf 0: alice_npub (verified via AccountIdentityProof)
    Leaf 1: bob_npub (himself)
    Leaf 2: carol_npub
    Leaf 3: david_npub
```

Carol and David do the same independently.

---

## Step 12 — David Sends a Message

```
Plaintext: "Hello group!"

12a. Inner payload (unsigned Nostr event shape):
     { pubkey: david_npub, kind: 9, content: "Hello group!", tags: [...] }

12b. MLS encrypt:
     mls_group.create_message(payload)
     -> MLS PrivateMessage (AES-128-GCM, David's sender key from epoch 1)
     -> The MLS message is signed by david_ed25519 via mls_sign -> KeyMaster

12c. Outer seal:
     key   = group_event_key (epoch 1)
     nonce = random(12)
     ct    = ChaCha20Poly1305(key, nonce, mls_message_bytes)

12d. Nostr event:
     kind:    445
     pubkey:  eph_5.pub       <- David's fresh throwaway key (local)
     content: base64(nonce || ct)
     tags:    [["h", transport_group_id]]
     sig:     BIP-340_Sign(eph_5.sec, event_id)

-> relays
```

---

## Step 13 — Alice Decrypts David's Message

```
Alice sees kind-445 with matching "h" tag

13a. Verify event signature (eph_5.pub) — integrity OK
13b. base64 decode -> 12-byte nonce + ciphertext
13c. ChaCha20Poly1305_Decrypt(group_event_key, nonce, ct) -> MLS bytes
13d. MLS processes PrivateMessage:
     - Identifies sender leaf index
     - AES-128-GCM decrypt with David's sender key
     - MLS authenticates David via ed25519 signature
     - Recovers: { pubkey: david_npub, content: "Hello group!" }
13e. Verify david_npub matches leaf credential
13f. Display: "David: Hello group!"
```

This step is identical to the nsec-based flow. Decryption uses symmetric
keys from the MLS key schedule — no KeyMaster interaction needed.

---

## Summary of Keys Used Per Person

```
From HD seed via KeyMaster (never leaves KeyMaster):
  Nostr branch (m/44'/1237'/...):
    +-- npub = Nostr + Marmot identity
    +-- Signs Nostr events (KeyPackage publication, relay lists)
    +-- Signs AccountIdentityProof (binds npub <-> ed25519)
    +-- NIP-44 ECDH for welcome seal/unseal

  MLS branch (m/44'/1242'/...):
    +-- Ed25519 signing key: signs all MLS operations
    +-- X25519 HPKE init keys: one per KeyPackage, index increments

Locally generated (NOT from HD seed):
  +-- Ephemeral secp256k1 keys for kind-445 events (used once, discarded)

Derived per epoch (from MLS key schedule, local):
  +-- Per-sender AES-128-GCM keys (inner MLS message encryption)
  +-- ChaCha20-Poly1305 key (outer kind-445 transport encryption)
```

## What Crosses the KeyMaster Boundary

| Direction | Data | Purpose |
|---|---|---|
| Client -> KeyMaster | `connect()` | Attach account to Whitenoise |
| KeyMaster -> Client | Nostr pubkey (alice_npub) | Account identifier |
| Client -> KeyMaster | `get_mls_pubkey(device_id, "0x0001")` | Get MLS signing key |
| KeyMaster -> Client | Ed25519 public key | MLS identity |
| Client -> KeyMaster | `mls_next_hpke_init_key(current_pubkey)` | Get next HPKE key |
| KeyMaster -> Client | X25519 public key | For KeyPackage |
| Client -> KeyMaster | `mls_sign(data)` | Sign MLS content |
| KeyMaster -> Client | Ed25519 signature | 64 bytes |
| Client -> KeyMaster | `mls_hpke_decap(pubkey, kem_output)` | Welcome decapsulation |
| KeyMaster -> Client | Raw DH shared secret | 32 bytes |
| Client -> KeyMaster | Nostr event hash | Sign Nostr events |
| KeyMaster -> Client | BIP-340 Schnorr signature | 64 bytes |

Private keys, the mnemonic, and derivation paths never cross the boundary.

## What the Relay Sees

| Event | Relay knows | Relay cannot know |
|---|---|---|
| kind 30443 (KeyPackages) | Who published it (npub is public) | Nothing secret — intentionally public |
| kind 1059 (Welcomes) | Recipient (`p` tag), ephemeral sender | Real sender, content, that the 3 events are related |
| kind 445 (Messages) | Group transport ID (`h` tag), ephemeral sender | Who sent it, what it says, how many members exist |

## Differences from nsec-Based Flow

| Aspect | nsec-based | HD seed |
|---|---|---|
| Key origin | nsec imported, Ed25519/X25519 random | All derived from mnemonic |
| Private key location | Client device (keyring + SQLCipher) | KeyMaster process only |
| Vault | vault.db with Argon2id + XChaCha20Poly1305 | None |
| Recovery | vault.db backup + password | Mnemonic only |
| Signing | Local crypto operations | Remote call to KeyMaster |
| HPKE decap | Local X25519 private key | Remote call to KeyMaster |
| HPKE key selection | OpenMLS tracks index internally | Client passes pubkey from relay |
| Symmetric crypto | Local (RustCrypto) | Local (RustCrypto) — unchanged |
| Ephemeral keys | Local random | Local random — unchanged |
| AccountIdentityProof | Same structure | Same structure |
| Verifier perspective | Identical | Identical — cannot tell the difference |
