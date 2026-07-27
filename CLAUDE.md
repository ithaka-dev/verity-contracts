# verity-contracts — agent instructions

**This repository implements decisions made in
[verity-foundation](https://github.com/ithaka-dev/verity-foundation/blob/main/../..). It does not make them.**

Before substantive work, read:
1. [`docs/Verity-spec.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — §7 holds the ten invariants
2. [`docs/decisions/`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions) — the ADRs listed below bind this repo directly
3. [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md) — where this repo's issues sit in the sequence

**If something here seems undecided, it probably isn't.** Search the ADRs before deciding it in a
pull request. If it is genuinely undecided, it belongs in an ADR upstream — not in code here.

## Binding decisions

[ADR 0003](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0003-holder-initiated-upgrades.md) ·
[ADR 0004](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0004-upgrade-mechanics.md) ·
[ADR 0005](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0005-design-for-smart-accounts-implement-eoa.md) ·
[ADR 0006](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0006-appmanifest-version-record.md) ·
[ADR 0008](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0008-upgrade-is-in-place.md) ·
[ADR 0010](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0010-export-capability.md) ·
[ADR 0011](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0011-app-identity-is-manifest-address.md)

## Hard rules

- **Never call `ecrecover` directly.** Route through the dispatching helper (ERC-1271, ERC-6492). The smart-account branch **rejects explicitly** with a "not supported in MVP" error rather than falling through to an EOA assumption. Build the helper *first* — build it later and something already bypasses it.
- **App identity is the `AppManifest` address.** `tokenId = keccak256(manifestAddress, version)`. No registry, no registration, no privileged writer — that is what makes the no-gatekeeper property structural rather than a policy someone maintains.
- **Version entries are append-only**, developer-writer-only (I5).
- **Capabilities are a bitmap** (`health`, `migrate`, `export`) — never an enum tier. Capabilities have no natural ordering.
- **Burn and mint may be atomic** — nothing in state migration depends on holding the old license (ADR 0008).

## The record

`{ imageDigest, composeHash, composeURI, capabilities, metadataHash, metadataURI }`

The license binds to **`composeHash`**. `imageDigest` stays in the record and is what the verifier
cross-checks the compose against — that cross-check is the only digest-pinning enforcement an
attacker cannot route around.
