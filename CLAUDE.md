# Project Instructions

This repository holds architecture and protocol design documents for
WhiteNoise, Marmot, and the KeyMaster signing-agent integration. It
contains documentation only — no code.

## This repository is shareable

Treat everything here as publicly readable, whatever the current
GitHub visibility setting says.

Do not add:

- Internal hostnames or addresses — `*.h3`, `osn00`, `px01`, `s02`,
  `172.16.*`, `vcs-user`, Phorge, VPN details.
- References to workspace planning — mission plans, `plan/` paths,
  roadmap items, ways-of-working documents. State the conclusion
  inline instead of linking to where it was decided.
- Real identities, key material, mnemonics, or relay credentials.

Before pushing, check:

```sh
grep -rnE '\b[a-z0-9-]+\.h3\b|osn00|px01|172\.16\.|vcs-user|Phorge|plan/|mission-[0-9]' \
  --include='*.md' . | grep -v '^\./CLAUDE.md:'
```

It should return nothing.

## Test cast

All examples use fictional characters — Alice, Bob, Claire, David,
Eve — with `@atlanta.com`, `@biloxi.com` style addresses. Never use a
real identity, even as an illustration.

## Writing

- One topic per document. If a document needs two titles, it is two
  documents.
- Diagrams are mermaid, in fenced blocks, so they render on GitHub.
- Link between documents with relative paths. Check them after moving
  a file.
- When a document describes something the code does, name the file and
  symbol so a reader can verify it. When it describes something
  planned but not built, say so in the document, at the top.

## Keeping it true

A design document that contradicts the code is worse than no document.
If you find drift, either correct the document or mark it superseded
at the top — do not leave it looking authoritative.

## Git Commit Rules

- NEVER use `--no-gpg-sign` when committing. Let GPG signing run
  naturally. If it fails, report the failure rather than bypassing it.
- Do not add `Co-Authored-By` trailers to commit messages.
