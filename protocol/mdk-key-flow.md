# MDK Key Flow: Test Case → Engine → OpenMLS

How the different key materials flow from test setup through the MDK engine into OpenMLS.

## Key Material Overview

| Key | Type | Origin | Purpose |
|-----|------|--------|---------|
| Account key (private) | secp256k1 Schnorr | Test seed → SHA256 loop | Signs account identity proof |
| Account identity | 32-byte x-only secp256k1 pubkey | Derived from account key | Credential identity in every leaf node |
| MLS signer (private) | Ed25519 | OpenMLS `SignatureKeyPair::new()` | Signs MLS messages, commits, key packages |
| MLS signature pubkey | Ed25519 | Derived from MLS signer | Embedded in leaf node `signature_key` |
| HPKE init key | X25519 | OpenMLS KeyPackage builder | Encrypts Welcome messages to recipient |
| Group application key | AES-128-GCM | Tree-derived per epoch (HKDF) | Encrypts/decrypts application messages |

## 1. Engine Build — Identity Setup

```mermaid
sequenceDiagram
    participant T as Test
    participant EB as EngineBuilder
    participant I as Identity
    participant S as SqliteStorage
    participant OML as OpenMLS

    Note over T: seed = b"alice"

    T->>T: SHA256("cgka-engine-test-identity-v1" || seed || counter)<br/>until valid secp256k1 SigningKey found
    T->>T: account_privkey = SigningKey (secp256k1)
    T->>T: account_pubkey = account_privkey.verifying_key().to_bytes() (32 bytes, x-only)

    T->>EB: .identity(account_pubkey)
    T->>EB: .account_identity_proof_signer(Arc(TestSigner(account_privkey)))
    T->>EB: .peeler(Box(RelayPeeler))
    T->>EB: .build()

    EB->>I: Identity::load_or_generate(ciphersuite, account_pubkey, storage, proof_signer)
    I->>I: validate_credential_identity(account_pubkey)<br/>k256::schnorr::VerifyingKey::from_bytes (BIP-340 check)

    I->>S: account_device_signer(&MemberId(account_pubkey))?
    alt First run (no stored signer)
        S-->>I: None
        I->>OML: SignatureKeyPair::new(Ed25519)
        OML-->>I: mls_signer (Ed25519 keypair)
        I->>OML: mls_signer.store(mls_storage)
        I->>S: put_account_device_signer(account_pubkey → mls_signer.public())
    else Subsequent run
        S-->>I: AccountDeviceSignerBinding { mls_signature_public_key }
        I->>OML: SignatureKeyPair::read(storage, mls_pubkey, Ed25519)
        OML-->>I: mls_signer (loaded from storage)
    end

    I->>I: from_signer(mls_signer, account_pubkey, ciphersuite, proof_signer)
```

## 2. Account Identity Proof — Binding Account Key to MLS Key

```mermaid
sequenceDiagram
    participant I as Identity::from_signer
    participant P as AccountIdentityProof
    participant PS as TestSigner (secp256k1)

    I->>I: credential = BasicCredential::new(account_pubkey)
    I->>I: credential_with_key = { credential, signature_key: mls_signer.public() }

    I->>P: account_identity_proof_extension(<br/>  account_pubkey,<br/>  mls_signer.public(),<br/>  ciphersuite,<br/>  Ed25519,<br/>  proof_signer)

    P->>P: request = AccountIdentityProofRequest {<br/>  account_identity: account_pubkey (32 bytes),<br/>  mls_signature_public_key: Ed25519 pubkey,<br/>  ciphersuite: 0x0001,<br/>  signature_scheme: Ed25519 }

    P->>P: Build Nostr Kind-450 unsigned event:<br/>  pubkey = account_pubkey<br/>  created_at = 0<br/>  tags = [d, extension, version,<br/>          ciphersuite, signature_scheme,<br/>          mls_signature_key]

    P->>P: proof_event_id = SHA256(canonical event JSON) → 32 bytes

    P->>PS: sign_account_identity_proof(&request)
    PS->>PS: Verify account_pubkey matches signer's verifying_key
    PS->>PS: sign_prehash(proof_event_id) using secp256k1 private key
    PS-->>P: signature (64-byte Schnorr)

    P->>P: Encode as Extension(type=0xF2F1, proof_bytes)
    P-->>I: account_identity_proof_extension

    Note over I: Identity now holds:<br/>• signer: Ed25519 (MLS signing)<br/>• credential_with_key: account_pubkey + Ed25519 pubkey<br/>• self_id: MemberId(account_pubkey)<br/>• proof_extension: Schnorr sig binding both keys
```

## 3. KeyPackage Creation

```mermaid
sequenceDiagram
    participant T as Test
    participant E as Engine
    participant OML as OpenMLS
    participant KP as KeyPackage (wire)

    T->>E: engine.fresh_key_package()

    E->>E: leaf_extensions = [<br/>  app_components_extension,<br/>  account_identity_proof_extension (from Identity)]

    E->>OML: MlsKeyPackage::builder()<br/>  .leaf_node_capabilities(caps)<br/>  .leaf_node_extensions(leaf_extensions)<br/>  .mark_as_last_resort()<br/>  .build(ciphersuite, provider,<br/>         identity.signer,<br/>         identity.credential_with_key)

    Note over OML: OpenMLS internally:

    OML->>OML: Generate HPKE init keypair (X25519)<br/>for Welcome encryption
    OML->>OML: Create LeafNode {<br/>  credential: BasicCredential(account_pubkey),<br/>  signature_key: Ed25519 pubkey,<br/>  extensions: [proof, app_components],<br/>  capabilities: [...] }
    OML->>OML: Sign LeafNode with Ed25519 signer
    OML->>OML: Create KeyPackage {<br/>  leaf_node,<br/>  init_key: X25519 pubkey,<br/>  lifetime, ... }
    OML->>OML: Sign KeyPackage with Ed25519 signer

    OML-->>E: KeyPackageBundle

    E->>E: TLS serialize → bytes
    E-->>T: KeyPackage { bytes }

    Note over KP: Wire format contains:<br/>• credential.identity = account_pubkey (32 bytes)<br/>• signature_key = Ed25519 pubkey<br/>• init_key = X25519 pubkey (for Welcome enc)<br/>• extensions[0xF2F1] = proof binding both keys<br/>• signature = Ed25519 over KeyPackage
```

## 4. Group Creation + Welcome

```mermaid
sequenceDiagram
    participant T as Test
    participant A as Alice Engine
    participant OML as OpenMLS
    participant P as RelayPeeler

    T->>A: create_group(name, [bob_kp])

    A->>A: Parse bob_kp bytes → OpenMLS KeyPackage
    A->>A: Validate Bob's credential identity (BIP-340)
    A->>A: Validate Bob's account_identity_proof extension

    A->>OML: MlsGroup::new(provider, alice.signer, config, alice.credential_with_key)
    Note over OML: Creates group at epoch 0<br/>Alice's LeafNode in tree position 0<br/>Signs initial group context with Ed25519

    A->>OML: mls_group.add_members(provider, alice.signer, [bob_kp])
    Note over OML: 1. Stages Add proposal for Bob<br/>2. Creates Commit (epoch 0→1) signed by Alice (Ed25519)<br/>3. Derives Welcome for Bob:<br/>   - GroupInfo encrypted with Bob's<br/>     HPKE init key (X25519 from his KP)<br/>   - Welcome contains encrypted group secrets

    OML-->>A: (commit, welcome, group_info)

    A->>OML: mls_group.merge_pending_commit()
    Note over OML: Alice now at epoch 1<br/>Tree has both Alice + Bob leaves

    A->>P: wrap_welcome(EncryptedPayload{ciphertext: welcome_bytes}, bob_member_id)
    P-->>A: TransportMessage { payload: welcome_bytes, envelope: Welcome{recipient: bob_id} }

    A->>P: wrap_group_message(EncryptedPayload{ciphertext: commit_bytes}, ctx)
    P-->>A: TransportMessage { payload: commit_bytes, envelope: GroupMessage{transport_group_id} }

    A-->>T: SendResult::GroupCreated { welcomes: [bob_welcome], pending }

    T->>A: confirm_published(pending)
    Note over A: Marks commit as durably published
```

## 5. Welcome Join (Bob)

```mermaid
sequenceDiagram
    participant T as Test
    participant B as Bob Engine
    participant P as RelayPeeler
    participant OML as OpenMLS
    participant V as Proof Validator

    T->>B: join_welcome(welcome_transport_msg)

    B->>B: Check envelope.recipient == bob.self_id (account_pubkey)

    B->>P: peel_welcome(&welcome_msg)
    P-->>B: PeeledMessage { content: Welcome{bytes: mls_welcome_bytes} }

    B->>OML: MlsMessageIn::tls_deserialize(mls_welcome_bytes)
    OML-->>B: Welcome message

    B->>OML: ProcessedWelcome::new_from_welcome(provider, config, welcome)
    Note over OML: Finds matching KeyPackage in local storage<br/>(by HPKE init key reference in Welcome)<br/>Decrypts GroupInfo using Bob's HPKE private key (X25519)<br/>Extracts group secrets (tree, epoch keys)

    B->>OML: processed.into_staged_welcome(provider)
    Note over OML: Reconstructs ratchet tree<br/>Verifies all signatures in tree

    B->>OML: staged.into_group(provider)
    OML-->>B: MlsGroup (Bob now has full tree at epoch 1)

    B->>V: validate_member_credentials_and_account_proofs(mls_group, ciphersuite)
    loop For each leaf node in tree
        V->>V: Extract BasicCredential.identity (account_pubkey, 32 bytes)
        V->>V: validate_credential_identity (BIP-340 check)
        V->>V: Extract extension 0xF2F1 (account_identity_proof)
        V->>V: Decode proof → { request, signature }
        V->>V: Verify proof.account_identity == credential.identity
        V->>V: Verify proof.mls_signature_public_key == leaf.signature_key
        V->>V: Verify proof.ciphersuite == expected
        V->>V: Reconstruct Nostr Kind-450 event from request fields
        V->>V: Verify Schnorr signature over event_id<br/>using account_pubkey (secp256k1)
    end

    B-->>T: group_id (Bob has joined)
```

## 6. Application Message Send + Receive

```mermaid
sequenceDiagram
    participant A as Alice Engine
    participant OML_A as OpenMLS (Alice)
    participant P as RelayPeeler
    participant Relay as strfry Relay
    participant OML_B as OpenMLS (Bob)
    participant B as Bob Engine

    Note over A: Alice sends "hello from alice"

    A->>A: payload = MarmotAppEvent::new(<br/>  pubkey=hex(alice_account_pubkey),<br/>  kind=9, content="hello from alice"<br/>).encode()

    A->>OML_A: mls_group.create_message(provider, alice.signer, &payload)
    Note over OML_A: 1. Derive application key from tree (HKDF)<br/>   key = epoch_secret → application_secret → AES-128-GCM key<br/>2. Encrypt payload with AES-128-GCM<br/>3. Sign ciphertext with Alice's Ed25519 signer<br/>4. Ratchet application secret forward

    OML_A-->>A: MlsMessageOut (encrypted + signed)

    A->>A: TLS serialize → ciphertext_bytes
    A->>P: wrap_group_message(ciphertext_bytes, group_context)
    P-->>A: TransportMessage { payload: ciphertext_bytes }

    A->>A: route: set envelope.transport_group_id = group_id

    A-->>Relay: Publish as Nostr event (kind 445, h-tag=group_id)

    Relay-->>B: Fetch event, reconstruct TransportMessage

    B->>P: peel_group_message(&msg, &group_context_snapshot)
    P-->>B: PeeledMessage { content: MlsMessage{bytes: ciphertext_bytes} }

    B->>OML_B: mls_group.process_message(provider, ciphertext_bytes)
    Note over OML_B: 1. Identify sender leaf by leaf index in MLS header<br/>2. Derive matching application key (same HKDF tree)<br/>3. Decrypt with AES-128-GCM<br/>4. Verify Ed25519 signature using sender's leaf.signature_key<br/>5. Extract sender credential.identity = alice_account_pubkey

    OML_B-->>B: ProcessedMessageContent::ApplicationMessage(payload_bytes)

    B->>B: sender_id = credential.identity from sender's leaf
    B->>B: Validate MarmotAppEvent.pubkey == hex(sender_id)
    B->>B: Emit GroupEvent::MessageReceived {<br/>  sender: alice_account_pubkey,<br/>  payload: MarmotAppEvent JSON }
```

## 7. Complete Key Relationship Diagram

```mermaid
graph TD
    subgraph "Test Layer"
        SEED["seed (b'alice')"]
        SK["secp256k1 SigningKey<br/>(account private key)"]
        VK["32-byte x-only pubkey<br/>(account identity)"]
        SEED -->|"SHA256 loop<br/>until valid"| SK
        SK -->|".verifying_key()"| VK
    end

    subgraph "MDK Engine Layer"
        BI["BasicCredential(identity)"]
        MID["MemberId(identity)"]
        VK -->|"identity bytes"| BI
        VK -->|"self_id"| MID

        MLS_SK["Ed25519 SignatureKeyPair<br/>(MLS signer, random)"]
        MLS_PK["Ed25519 pubkey"]
        MLS_SK -->|".public()"| MLS_PK

        CWK["CredentialWithKey {<br/>credential: BasicCredential,<br/>signature_key: Ed25519 pubkey}"]
        BI --> CWK
        MLS_PK --> CWK

        PROOF["AccountIdentityProof {<br/>Nostr Kind-450 event<br/>+ 64-byte Schnorr sig}"]
        VK -->|"account_identity"| PROOF
        MLS_PK -->|"mls_signature_public_key"| PROOF
        SK -->|"signs proof_event_id"| PROOF

        EXT["Extension 0xF2F1<br/>(embedded in leaf node)"]
        PROOF --> EXT
    end

    subgraph "OpenMLS Layer"
        LEAF["LeafNode {<br/>credential,<br/>signature_key,<br/>extensions}"]
        CWK --> LEAF
        EXT --> LEAF
        MLS_SK -->|"signs leaf"| LEAF

        HPKE["HPKE init keypair<br/>(X25519, per KeyPackage)"]

        KP["KeyPackage {<br/>leaf_node,<br/>init_key}"]
        LEAF --> KP
        HPKE -->|"pubkey"| KP
        MLS_SK -->|"signs KeyPackage"| KP

        GROUP["MlsGroup (ratchet tree)"]
        KP -->|"add_members"| GROUP
        LEAF -->|"creator leaf"| GROUP

        APP_KEY["Application Key<br/>(AES-128-GCM,<br/>tree-derived per epoch)"]
        GROUP -->|"HKDF key schedule"| APP_KEY

        WELCOME["Welcome {<br/>GroupInfo encrypted with<br/>recipient's X25519 init key}"]
        GROUP --> WELCOME
        HPKE -->|"encrypt GroupInfo"| WELCOME
    end

    subgraph "Verification (on join)"
        V1["1. credential.identity is valid<br/>x-only secp256k1 (BIP-340)"]
        V2["2. Extension 0xF2F1 present"]
        V3["3. proof.account_identity<br/>== credential.identity"]
        V4["4. proof.mls_signature_key<br/>== leaf.signature_key"]
        V5["5. Schnorr sig verifies over<br/>Kind-450 event using<br/>account_identity pubkey"]
        LEAF --> V1
        LEAF --> V2
        V2 --> V3
        V2 --> V4
        V2 --> V5
    end

    style SEED fill:#e1f5fe
    style SK fill:#fff3e0
    style VK fill:#fff3e0
    style MLS_SK fill:#e8f5e9
    style MLS_PK fill:#e8f5e9
    style HPKE fill:#f3e5f5
    style APP_KEY fill:#fce4ec
    style PROOF fill:#fff3e0
```

## Ciphersuite

All operations use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`:

| Component | Algorithm |
|-----------|-----------|
| Key Exchange (HPKE) | X25519 |
| Encryption | AES-128-GCM |
| Hash | SHA-256 |
| Signature | Ed25519 |

The account identity key (secp256k1 Schnorr) is **not** part of the MLS ciphersuite. It exists at the Marmot protocol layer to bind a Nostr identity to the MLS signing key via the account identity proof extension.
