# WhiteNoise Design Documents

Architecture and protocol design for the WhiteNoise client, the Marmot
protocol binding, and the KeyMaster signing-agent integration.

These documents describe how the system is designed and why. They are
not API reference for any single crate — each repository documents its
own surface. What lives here is the material that spans repositories:
key derivation, the signing-agent contract, and the message flows that
cross between `openmls`, `mdk`, `wn-kv-test` and the client.

## Layout

| Directory | Contents |
|-----------|----------|
| `key-management/` | How keys are derived, stored, and used |
| `signing-agent/` | The external signer contract |
| `protocol/` | Key and message flow through the stack |
| `examples/` | End-to-end walkthroughs with the test cast |

## Start here

| Document | Read it for |
|----------|-------------|
| [key-management/key-management-overview.md](key-management/key-management-overview.md) | Comparison of every key-management mode. The orientation document. |
| [protocol/mdk-key-flow.md](protocol/mdk-key-flow.md) | Which keys MDK uses and how they reach OpenMLS. Seven sequence diagrams. |
| [protocol/nostr-message-flow.md](protocol/nostr-message-flow.md) | Which Nostr events cross the wire when one user messages another. |
| [signing-agent/signing-agent-api.md](signing-agent/signing-agent-api.md) | The 11 JSON-RPC methods, with request and response shapes. |

## key-management/

| Document | Contents |
|----------|----------|
| [key-management-overview.md](key-management/key-management-overview.md) | Every key-management mode, compared |
| [keyvault-mls-design.md](key-management/keyvault-mls-design.md) | BIP-32 derivation paths, shared vs device-bound modes |
| [account-creation-flow.md](key-management/account-creation-flow.md) | The three account-creation paths |
| [hpke-vault-decryption.md](key-management/hpke-vault-decryption.md) | Welcome decryption through a vault-backed provider |

## signing-agent/

| Document | Contents |
|----------|----------|
| [signing-agent-api.md](signing-agent/signing-agent-api.md) | The 11 JSON-RPC methods over the Unix socket |
| [mls-signer-api.md](signing-agent/mls-signer-api.md) | Protocol-level signer API |

## protocol/

| Document | Contents |
|----------|----------|
| [mdk-key-flow.md](protocol/mdk-key-flow.md) | Test case → engine → OpenMLS, with diagrams |
| [nostr-message-flow.md](protocol/nostr-message-flow.md) | Nostr event kinds and the chat-opening exchange |

## examples/

| Document | Contents |
|----------|----------|
| [group-creation-example.md](examples/group-creation-example.md) | Four people create a group, starting from nsec only |
| [group-creation-example-hdseed.md](examples/group-creation-example-hdseed.md) | The same walkthrough with HD seed derivation |

## Related repositories

| Repository | What it is |
|------------|------------|
| `openmls` | MLS protocol implementation (fork) |
| `mdk` | Marmot Development Kit — engine, session, app (fork) |
| `wn-kv-test` | Signing agent — daemon, client, RPC types |
| `keyvault-rs` | BIP-32 key derivation |
| [marmot-protocol/marmot](https://github.com/marmot-protocol/marmot) | The Marmot protocol specification |

## Conventions

All examples use fictional characters — Alice, Bob, Claire, David,
Eve. No document here contains real identities, key material, or
infrastructure detail.
