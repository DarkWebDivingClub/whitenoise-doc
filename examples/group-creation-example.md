# Group Creation Example: Alice, Bob, Carol, and David

A concrete walkthrough of how four people with Nostr secret keys create an
encrypted group chat using Whitenoise and the Marmot protocol.

## Starting Point — Everyone Only Has an nsec

Each person has a Nostr secret key — a 32-byte secp256k1 scalar, typically in
bech32 form:

```
Alice: nsec1alice...  ->  alice_sec (32 bytes, secp256k1 scalar)
                      ->  alice_npub (32-byte x-only public key, derived)

Bob:   nsec1bob...    ->  bob_sec, bob_npub
Carol: nsec1carol...  ->  carol_sec, carol_npub
David: nsec1david...  ->  david_sec, david_npub
```

These are just raw Nostr identities. No MLS keys, no vault, no account, no
KeyPackages exist yet.

---

## Step 1 — Alice Opens Whitenoise and Creates an Account

Alice launches Whitenoise for the first time. She sets a vault password.

```
1a. Vault creation:
    salt = random(16 bytes)
    vault_key = Argon2id(password, salt, 19 MiB, 2 passes, 1 lane) -> 32 bytes

1b. Alice pastes/imports her nsec1alice...
    Keys::parse("nsec1alice...") -> nostr::Keys { secret: alice_sec, public: alice_npub }

1c. nsec stored in vault:
    vault["nsec:alice_hex"] = "nsec1alice..."
    vault["active_account"] = alice_hex
    nonce = random(24 bytes)
    ciphertext = XChaCha20Poly1305(vault_key, nonce, serialize(vault_map))
    -> written to $DM_HOME/vault.db

1d. Account created in AccountHome:
    $DM_HOME/accounts/alice/account.json = {
      label: "alice",
      account_id_hex: alice_hex,
      local_signing: true,
      signed_out: false
    }
    Secret stored via AccountSecretStore (file or keychain)

1e. MLS signing key generated (FIRST TIME, per device):
    alice_ed25519 = Ed25519::generate()   <- NOT derived from nsec, completely independent
    Stored in OpenMLS storage (SQLCipher DB)

1f. AccountIdentityProof — bind nsec to Ed25519 key:
    canonical = "marmot.account-identity-proof.v1" || 0x00 || 0xF2F1 || 0x01
              || 0x0001 || sig_scheme
              || len(alice_npub) || alice_npub
              || len(alice_ed25519.pub) || alice_ed25519.pub
    digest = SHA-256(canonical)
    proof_sig = BIP-340_Schnorr_Sign(alice_sec, digest)  <- nsec signs here

    This proof says: "I, alice_npub (secp256k1), authorize alice_ed25519.pub
                      as my MLS signing key"
```

At this point Alice has:

- Nostr identity: `alice_sec` / `alice_npub` (secp256k1, from her nsec)
- MLS identity: `alice_ed25519` (Ed25519, freshly generated)
- A cryptographic proof binding the two

---

## Step 2 — Alice Publishes a KeyPackage

Alice's app builds and publishes an MLS KeyPackage to her relays:

```
2a. KeyPackage built:
    alice_x25519 = X25519::generate()    <- HPKE init key, also independent

    KeyPackage {
      init_key: alice_x25519.pub,
      leaf_node: {
        signature_key: alice_ed25519.pub,
        credential: BasicCredential(alice_npub),  <- 32-byte Nostr identity
        extensions: [
          AccountIdentityProof { alice_npub, alice_ed25519.pub, proof_sig },
          AppComponents { ... }
        ]
      }
      signed by: alice_ed25519   <- MLS signature over the package
    }

2b. Published to relays as Nostr event:
    kind:    30443
    pubkey:  alice_npub
    content: base64(MLS-serialize(KeyPackage))
    tags:    [["d", random_slot_hex], ["mls_ciphersuite", "0x0001"], ...]
    sig:     BIP-340_Sign(alice_sec, event_id)   <- nsec signs the Nostr event
```

Two different keys sign two different things here:

- `alice_ed25519` signs the MLS KeyPackage (MLS layer)
- `alice_sec` (nsec) signs the Nostr event (transport layer)

---

## Step 3 — Bob, Carol, David Do the Same

Each person imports their nsec into Whitenoise and goes through the same setup.
Afterward:

```
Bob:
  nsec -> bob_npub (secp256k1)
  bob_ed25519 (Ed25519, device-local)
  AccountIdentityProof(bob_npub <-> bob_ed25519.pub)
  KeyPackage published (kind 30443), init_key: bob_x25519.pub

Carol:
  nsec -> carol_npub
  carol_ed25519, proof, KeyPackage (carol_x25519.pub)

David:
  nsec -> david_npub
  david_ed25519, proof, KeyPackage (david_x25519.pub)
```

---

## Step 4 — Alice Creates the MLS Group

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

## Step 5 — Alice Fetches KeyPackages from Relays

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

---

## Background: HPKE, the Ratchet Tree, and Path Secrets

Before diving into the commit, these three concepts need to be understood.
They are the machinery that makes MLS group encryption work.

### HPKE (Hybrid Public Key Encryption)

HPKE stands for **Hybrid Public Key Encryption** (RFC 9180). It combines three
primitives into a single encrypt-to-a-public-key operation:

```
HPKE = KEM + KDF + AEAD

1. KEM  (Key Encapsulation Mechanism)
   Sender uses the recipient's public key to produce:
     - a shared_secret (known to both sides)
     - an enc (encapsulated key, sent alongside the ciphertext)
   In Marmot's ciphersuite: DHKEM(X25519, HKDF-SHA256)
     - Sender generates an ephemeral X25519 keypair
     - Performs ECDH(ephemeral_secret, recipient_public) -> raw shared secret
     - Applies HKDF to derive the final shared_secret

2. KDF  (Key Derivation Function)
   Derives symmetric encryption keys from the shared_secret.
   In Marmot's ciphersuite: HKDF-SHA256

3. AEAD (Authenticated Encryption with Associated Data)
   Encrypts the plaintext payload using the derived symmetric key.
   In Marmot's ciphersuite: AES-128-GCM
```

The "hybrid" means it combines asymmetric key exchange (X25519 ECDH) with
symmetric encryption (AES-128-GCM). The sender only needs the recipient's
X25519 public key. The recipient decrypts using their X25519 private key.

In MLS, HPKE is used in two places:

1. **UpdatePath encryption** — when a committer distributes path secrets to
   co-path members, each path secret is HPKE-encrypted to the co-path node's
   X25519 public key.

2. **Welcome encryption** — the group secrets in a Welcome message are
   HPKE-encrypted to the invitee's KeyPackage init key (X25519).

### The MLS Ratchet Tree

The ratchet tree is the core data structure of MLS. It is a **left-balanced
binary tree** where each leaf represents a group member and each internal node
holds derived key material. The tree enables a single committer to update the
group's cryptographic state with cost proportional to log(N) rather than N.

#### Tree Structure with Alice, Bob, Carol, David

```
Node indices (RFC 9420 numbering):

                       [6]                    <- root
                      /   \
                   /         \
               [2]             [5]            <- intermediate nodes
              /   \           /   \
           [0]    [1]      [3]    [4]         <- leaves
          Alice   Bob     Carol   David
```

Nodes are numbered left-to-right, bottom-to-top. Leaves are at even indices
(0, 1, 3, 4 in this example — RFC 9420 uses a specific indexing scheme).
Each level of the tree serves a different purpose:

#### What Each Node Contains

**Leaf nodes** (one per member):

```
Leaf {
  hpke_public_key:   X25519 public key      <- for receiving encrypted path secrets
  signature_key:     Ed25519 public key      <- for signing MLS messages
  credential:        BasicCredential(npub)   <- the member's Nostr identity
  extensions: [
    AccountIdentityProof(npub <-> ed25519)   <- binds Nostr identity to MLS key
    AppComponents(...)                        <- supported features
  ]
}
```

Each member holds the corresponding **private keys** locally:
- X25519 private key (for decrypting path secrets addressed to them)
- Ed25519 private key (for signing commits, proposals, messages)

**Internal/parent nodes**:

```
ParentNode {
  hpke_public_key:   X25519 public key      <- derived from path_secret
  unmerged_leaves:   [leaf indices]          <- leaves that haven't been updated
}
```

Internal nodes do NOT have signature keys or credentials. They only hold an
HPKE key pair derived from a path secret. The private half is known to all
members in the node's subtree (because the path secret was distributed to them
during a commit).

**Blank nodes**: When a member is removed, their leaf is blanked (emptied).
Parent nodes on the removed member's path may also be blanked. Blank nodes
have no keys and are skipped during path computations.

#### How the Tree Enables Efficient Key Distribution

The key insight is that the tree creates a hierarchy of shared secrets. When
Alice commits, she only needs to encrypt path secrets for the nodes on her
**direct path** (leaf -> root). Each path secret is encrypted to the
**co-path** — the sibling node at each level:

```
Alice's direct path:  [0] -> [2] -> [6]
Alice's co-path:      [1] (Bob), [5] (Carol+David subtree)

To update the entire group, Alice encrypts:
  - path_secret for [2]: HPKE-encrypted to node [1]'s public key (Bob can decrypt)
  - path_secret for [6]: HPKE-encrypted to node [5]'s public key (Carol/David can decrypt)
```

This is O(log N) encryptions instead of O(N). With 1000 members, a committer
does ~10 HPKE encryptions, not 999.

#### Tree Invariant

Every member must be able to derive the keys for every node on their direct
path from leaf to root. After a commit, the committer's entire direct path
has fresh keys. Members in other subtrees receive the path secrets they need
via HPKE and derive the rest by walking up the tree.

### Path Secrets

A **path secret** is a random value assigned to each node on a committer's
direct path from their leaf to the root. It is the seed from which that
node's HPKE key pair is derived.

#### How Path Secrets Work in a Commit

When Alice creates a commit with an UpdatePath:

```
Step 1: Alice generates a new random HPKE key pair for her leaf.

Step 2: For each node on her direct path, derive a path secret:

  path_secret[leaf]   = random()
  path_secret[parent] = DeriveSecret(path_secret[child], "path")
                         (walk up the tree, deriving each parent from its child)

  In our 4-member tree:
    path_secret[node_2] = derived from Alice's new leaf secret
    path_secret[root_6] = DeriveSecret(path_secret[node_2], "path")

Step 3: Derive HPKE key pairs from each path secret:

  For each node on the direct path:
    (hpke_private, hpke_public) = DeriveKeyPair(path_secret[node])

  These become the new node keys in the ratchet tree.

Step 4: Encrypt path secrets to co-path nodes:

  Alice encrypts path_secret[node_2] to Bob's HPKE public key:
    HPKE.Seal(bob_leaf_hpke_pub, path_secret[node_2]) -> (enc, ct)

  Alice encrypts path_secret[root_6] to node_5's HPKE public key:
    HPKE.Seal(node_5_hpke_pub, path_secret[root_6]) -> (enc, ct)

  These encrypted path secrets are included in the UpdatePath.
```

#### How Recipients Process Path Secrets

When Bob receives Alice's commit:

```
Step 1: Bob finds himself on Alice's co-path at node [1] (sibling of [2]).

Step 2: Bob decrypts path_secret[node_2] using his leaf HPKE private key:
  path_secret[node_2] = HPKE.Open(bob_leaf_hpke_priv, enc, ct)

Step 3: Bob derives upward:
  path_secret[root_6] = DeriveSecret(path_secret[node_2], "path")

Step 4: Bob derives HPKE key pairs for nodes 2 and 6:
  (hpke_priv_2, hpke_pub_2) = DeriveKeyPair(path_secret[node_2])
  (hpke_priv_6, hpke_pub_6) = DeriveKeyPair(path_secret[root_6])

  Bob now knows all node keys from his leaf to the root.
```

Carol and David follow the same process but start from node [5] — they
decrypt `path_secret[root_6]` using node_5's HPKE private key.

#### Why Path Secrets Matter

The **root path secret** feeds into the commit_secret, which combines with
the prior epoch's init_secret to produce the new epoch_secret. This is the
starting point for the entire key schedule (per-sender keys, exporter
secrets, etc.). Path secrets are the mechanism by which a single committer's
action gives every group member the key material for the new epoch, without
any member needing to know any other member's private keys.

#### Forward Secrecy from Path Secrets

After processing a commit, members delete the path secrets and retain only
the derived node keys. If an attacker compromises a member's current state,
they cannot recover path secrets from previous epochs — those were used once
to derive keys and then discarded. Each commit produces fresh path secrets,
so compromising one epoch does not reveal past epochs (forward secrecy) or
future epochs (post-compromise security, once the compromised member commits).

---

## Step 6 — Alice Commits the Adds (Epoch Transition)

### What Is an Epoch

An epoch is a monotonically increasing counter (u64) scoped to a group. It
represents a snapshot of the group's cryptographic state: who the members are,
what the ratchet tree looks like, and what keys are available. Epoch 0 is the
initial state when the group is created. The epoch advances by exactly one
every time a **commit** is processed — commits are the *only* operation that
changes the epoch. Sending or receiving chat messages does not change the epoch.

### The Ratchet Tree Before the Commit

At epoch 0, Alice is the only member. The ratchet tree is:

```
Epoch 0 ratchet tree (left-balanced binary tree):

       [root]
         |
    [Alice_leaf]
      +-- HPKE key:      alice_leaf_x25519.pub  (X25519)
      +-- Signature key:  alice_ed25519.pub      (Ed25519)
      +-- Credential:     BasicCredential(alice_npub)
      +-- Extensions:     AccountIdentityProof(alice_npub <-> alice_ed25519.pub)
```

Each leaf in the ratchet tree holds:
- An **HPKE key pair** (X25519) — used for encrypting path secrets during commits
- A **signature key** (Ed25519) — used for signing MLS operations
- A **credential** — the member's Nostr identity (32-byte x-only pubkey)
- **Extensions** — including the AccountIdentityProof binding

Parent/intermediate nodes hold HPKE key pairs derived from path secrets.
The root secret feeds into the epoch's key schedule.

### The Epoch 0 Key Schedule

When the group is created at epoch 0, the MLS key schedule derives a tree of
secrets from the epoch_secret (RFC 9420, Section 8):

```
Epoch 0 key schedule:

  init_secret[0] + commit_secret
      |
      v
  epoch_secret (via HKDF-Extract + ExpandWithLabel with GroupContext)
      |
      +-- encryption_secret --> secret tree --> per-sender keys (AES-128-GCM)
      |                                        (only Alice exists, so 1 sender)
      |
      +-- exporter_secret  --> MLS-Exporter() API
      |     +-- ("marmot", "group-event", 32)              = group_event_key_0
      |     +-- ("marmot", "encrypted-media", 32)           = media_secret_0
      |     +-- ("marmot", "agent-text-stream-quic", 32)    = stream_secret_0
      |
      +-- confirmation_key   (for commit confirmation tags)
      +-- membership_key     (for membership tags on PublicMessage)
      +-- epoch_authenticator
      +-- external_secret
      +-- resumption_psk
      +-- init_secret[1]     (feeds into the NEXT epoch's key schedule)
```

The **secret tree** is a binary tree with one leaf per group member. The
encryption_secret sits at the root and is expanded downward. Each leaf derives
a **sender ratchet** — a hash chain that produces a fresh AES-128-GCM key and
nonce for each application message sent from that leaf. The ratchet advances
with every message, providing per-message forward secrecy within an epoch.

The **exporter secrets** are derived via:
```
DeriveSecret(exporter_secret, label) -> derived
ExpandWithLabel(derived, "exported", Hash(context), length) -> output
```
These are the keys Marmot uses for transport-level encryption (kind-445
events), encrypted media, and agent text streams.

### Alice Creates the Commit

Alice's engine stages a commit with three Add proposals:

```
6a. Stage the commit (publish-before-apply pattern):

    The engine requires EpochState == Stable before creating a commit.
    Alice is at Stable{epoch: 0}.

    mls_group.add_members([Bob_KP, Carol_KP, David_KP])
      -> produces: StagedCommit + MLS Welcome messages (one per invitee)

    The commit contains:
      - Proposal: Add(Bob's KeyPackage)
      - Proposal: Add(Carol's KeyPackage)
      - Proposal: Add(David's KeyPackage)
      - UpdatePath: Alice's new path keys (see below)

    Signed by: alice_ed25519

    Engine transitions: Stable{epoch:0} -> PendingPublish{epoch:1}
    The commit is NOT yet merged into local state.
```

### The UpdatePath — Alice's Key Rotation

Every commit includes an **UpdatePath**. This is how the committer rotates
their keys and distributes new path secrets to all group members:

```
6b. UpdatePath generation:

    Alice generates new keys for her leaf and every node on her
    direct path from leaf to root:

    New ratchet tree (epoch 1):

              [root]              <- new HPKE key from path_secret[root]
             /      \
        [node]      [node]        <- new HPKE keys from path_secret[nodes]
        /    \      /    \
    Alice   Bob  Carol  David     <- 4 leaves

    Alice's leaf:
      +-- NEW HPKE key:     alice_leaf_x25519_v2.pub  (freshly generated)
      +-- Signature key:    alice_ed25519.pub          (unchanged)
      +-- Credential:       BasicCredential(alice_npub)
      +-- Extensions:       AccountIdentityProof (unchanged)

    For each node on Alice's direct path (leaf -> root):
      1. Sample a fresh path_secret
      2. Derive an HPKE key pair from it: node_x25519 = DeriveKeyPair(path_secret)
      3. Encrypt path_secret to the co-path node's HPKE public key
         (so members in the other subtree can decrypt their portion)

    Bob, Carol, David each receive the path_secrets they need via
    HPKE encryption to their leaf HPKE keys (from their KeyPackages).
```

This means Alice's leaf encryption key rotates with every commit she creates.
The path secrets feed into the new epoch's key schedule, producing the
commit_secret that combines with init_secret[0] to derive epoch_secret[1].

### The New Epoch 1 Key Schedule

After the commit, epoch 1 has a completely new set of secrets:

```
6c. Epoch 1 key schedule:

  init_secret[0] + commit_secret (from UpdatePath)
      |
      v
  epoch_secret[1]
      |
      +-- encryption_secret --> secret tree (now 4 leaves)
      |     +-- Alice sender ratchet  -> per-message AES-128-GCM keys
      |     +-- Bob sender ratchet    -> per-message AES-128-GCM keys
      |     +-- Carol sender ratchet  -> per-message AES-128-GCM keys
      |     +-- David sender ratchet  -> per-message AES-128-GCM keys
      |
      +-- exporter_secret
      |     +-- group_event_key_1     (NEW — different from epoch 0)
      |     +-- media_secret_1        (NEW)
      |     +-- stream_secret_1       (NEW)
      |
      +-- confirmation_key, membership_key, ... (all new)
      +-- init_secret[1]             (feeds epoch 2)
```

Every secret is different from epoch 0. Someone who only has epoch 0 keys
cannot derive epoch 1 keys. This is **forward secrecy**: compromising epoch 0
keys does not reveal epoch 1 content.

### Publish-Before-Apply

Marmot uses a publish-before-apply pattern to handle unreliable transport:

```
6d. State machine transitions:

    Stable{epoch:0}
        |
        | Alice stages the commit
        v
    PendingPublish{epoch:1}
        |
        |--- on transport success ---> Merging ---> Stable{epoch:1}
        |                              mls_group.merge_pending_commit()
        |                              (key schedule advances here)
        |
        |--- on transport failure ---> Stable{epoch:0}
                                       mls_group.clear_pending_commit()
                                       (staged state discarded, no epoch change)
```

The commit is only merged into canonical local state after the relay confirms
receipt. If publishing fails, the staged commit is discarded and Alice stays
at epoch 0 — she can retry.

### Past Epoch Retention

The engine retains key material for `max_past_epochs = 5` previous epochs.
This means:
- At epoch 6, epochs 1-5 can still decrypt late-arriving messages
- At epoch 7, epoch 1 keys are discarded — messages from epoch 1 can no
  longer be decrypted
- This trades some forward secrecy for delivery robustness over unreliable
  relay transport

### What Can Trigger Future Epoch Changes

After the group is established, the epoch advances on any commit:

| Operation | Proposals in Commit | Effect |
|---|---|---|
| Invite new member | Add | New leaf added to tree |
| Remove member | Remove | Leaf blanked, tree pruned |
| Member leaves | SelfRemove (MIP-03) | Member removes own leaf |
| Update group settings | AppDataUpdate | Group profile, admin policy, etc. |
| Key update | Update (implicit) | Committer's leaf keys rotate |

Each commit also includes the committer's UpdatePath, rotating their leaf
keys. Every commit produces a new epoch with a completely fresh key schedule.

### GroupContextView — Caching Exporter Secrets

The engine eagerly computes all three exporter secrets when constructing a
GroupContextView, and caches them in a HashMap. The transport peeler (which
handles kind-445 encryption/decryption) reads from this cache rather than
calling export_secret() repeatedly:

```
GroupContextView {
  epoch: EpochId(1),
  secrets: {
    "marmot/group-event":              group_event_key_1,
    "marmot/encrypted-media":          media_secret_1,
    "marmot/agent-text-stream-quic":   stream_secret_1,
  },
  transport_group_id: Some(...)
}
```

If there is a pending commit, the view uses the *projected future epoch's*
exporter secrets instead of the current epoch's, so that outbound messages
are encrypted under the epoch the commit will produce.

---

## Step 7 — Alice Publishes the Commit (Kind 445)

```
MLS commit bytes
    |
ChaCha20-Poly1305:
    key   = epoch 0 group_event_key (only Alice has this)
    nonce = random(12)
    ct    = encrypt(key, nonce, mls_commit_bytes)
    |
Nostr kind-445 event:
    pubkey:  eph_1.pub           <- fresh secp256k1 keypair, used once, discarded
    content: base64(nonce || ct)
    tags:    [["h", transport_group_id]]
    sig:     BIP-340_Sign(eph_1.sec, event_id)

-> relays
```

---

## Step 8 — Alice Sends Welcomes via NIP-59

For each of Bob, Carol, David, Alice wraps a Welcome in three NIP-59 layers.
Here is Bob's:

```
--- Inner: MLS Welcome ---
  Encrypted TO bob_x25519.pub (from Bob's KeyPackage)
  Contains: epoch 1 ratchet tree, key schedule, member list
  Only bob_x25519.sec can open this

--- Rumor (kind 444, unsigned) ---
  pubkey:  alice_npub
  content: base64(MLS Welcome bytes)
  tags:    [["e", bob_keypackage_event_id],
            ["relays", "wss://relay1", ...]]

--- Seal (kind 13) ---
  NIP-44 ECDH shared secret: ecdh(alice_sec, bob_npub)
  content: NIP-44_Encrypt(rumor, shared_secret)
  signed by: alice_sec (BIP-340)

  This layer hides the rumor from the relay but lets
  Bob learn that ALICE is the sender.

--- Gift Wrap (kind 1059) ---
  NIP-44 ECDH shared secret: ecdh(eph_2.sec, bob_npub)
  content: NIP-44_Encrypt(seal, shared_secret)
  pubkey:  eph_2.pub             <- another fresh ephemeral key
  tags:    [["p", bob_npub]]
  signed by: eph_2.sec

  This layer hides Alice's identity from the relay.
  Relay only sees: "eph_2 sent something to bob_npub"

-> Published to Bob's inbox relays (kind 10050)
```

Alice repeats with `eph_3` for Carol, `eph_4` for David. Each Welcome is
independently encrypted to the recipient's X25519 init key, and independently
gift-wrapped with a unique ephemeral Nostr key.

---

## Step 9 — Bob Receives the Welcome

```
Bob sees kind 1059 addressed to bob_npub on his inbox relay

9a. Unwrap gift wrap:
    shared = NIP-44_ECDH(bob_sec, eph_2.pub)
    -> recovers Seal (kind 13)

9b. Unwrap seal:
    shared = NIP-44_ECDH(bob_sec, alice_npub)
    -> recovers Rumor (kind 444)
    -> Bob now knows Alice sent the invite

9c. Decode MLS Welcome:
    welcome_bytes = base64_decode(rumor.content)

9d. Process MLS Welcome:
    OpenMLS decrypts using bob_x25519.sec (private init key from Bob's KeyPackage)
    -> Bob receives: full ratchet tree, epoch 1 key schedule, group_id
    -> Bob derives: group_event_key, media_secret, etc.
    -> Bob can now decrypt kind-445 messages for this group

9e. Bob sees the member list:
    Leaf 0: alice_npub (verified via AccountIdentityProof)
    Leaf 1: bob_npub (himself)
    Leaf 2: carol_npub
    Leaf 3: david_npub
```

Carol and David do the same independently.

---

## Step 10 — David Sends a Message

```
Plaintext: "Hello group!"

10a. Inner payload (unsigned Nostr event shape):
     { pubkey: david_npub, kind: 9, content: "Hello group!", tags: [...] }

10b. MLS encrypt:
     mls_group.create_message(david_ed25519, payload)
     -> MLS PrivateMessage (AES-128-GCM, David's sender key from epoch 1)

10c. Outer seal:
     key   = group_event_key (epoch 1)
     nonce = random(12)
     ct    = ChaCha20Poly1305(key, nonce, mls_message_bytes)

10d. Nostr event:
     kind:    445
     pubkey:  eph_5.pub       <- David's fresh throwaway key
     content: base64(nonce || ct)
     tags:    [["h", transport_group_id]]
     sig:     BIP-340_Sign(eph_5.sec, event_id)

-> relays
```

---

## Step 11 — Alice Decrypts David's Message

```
Alice sees kind-445 with matching "h" tag

11a. Verify event signature (eph_5.pub) — integrity OK
11b. base64 decode -> 12-byte nonce + ciphertext
11c. ChaCha20Poly1305_Decrypt(group_event_key, nonce, ct) -> MLS bytes
11d. MLS processes PrivateMessage:
     - Identifies sender leaf index
     - AES-128-GCM decrypt with David's sender key
     - MLS authenticates David via ed25519 signature
     - Recovers: { pubkey: david_npub, content: "Hello group!" }
11e. Verify david_npub matches leaf credential
11f. Display: "David: Hello group!"
```

---

## Summary of Keys Used Per Person

```
From nsec (secp256k1):
  +-- npub = Nostr + Marmot identity
  +-- Signs Nostr events (KeyPackage publication, relay lists)
  +-- Signs AccountIdentityProof (binds nsec <-> ed25519)
  +-- NIP-44 ECDH for welcome seal/unseal
  +-- NIP-59 gift wrap decrypt (as recipient)

Generated on first launch (Ed25519):
  +-- Signs all MLS operations (commits, proposals, messages)

Generated per KeyPackage (X25519):
  +-- Welcome recipients decrypt MLS Welcome with this

Generated per outbound kind-445 event (ephemeral secp256k1):
  +-- Signs outer Nostr event, used once, discarded

Derived per epoch (from MLS key schedule):
  +-- Per-sender AES-128-GCM keys (inner MLS message encryption)
  +-- ChaCha20-Poly1305 key (outer kind-445 transport encryption)
```

## What the Relay Sees

| Event | Relay knows | Relay cannot know |
|---|---|---|
| kind 30443 (KeyPackages) | Who published it (npub is public) | Nothing secret here — intentionally public |
| kind 1059 (Welcomes) | Recipient (`p` tag), ephemeral sender | Real sender, content, that the 3 events are related |
| kind 445 (Messages) | Group transport ID (`h` tag), ephemeral sender | Who sent it, what it says, how many members exist |
