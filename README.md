# verity-contracts

> ## 🚧 Not functional — do not adopt
>
> This repository is **scaffolding**. It does not yet do the thing its description says it does.
> Nothing here is ready to depend on, build against, or copy.
>
> These contracts are unaudited and not deployed to any network you should rely on. Deployed
> contracts are effectively immutable — adopting an early version means adopting it permanently.
>
> **Readiness is per-repo and will be announced by removing this banner** and tagging a release.
> Until then, treat anything here as subject to change without notice — including its public
> interface, its behaviour, and its existence.
>
> Sequence and current position: [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md).

Solidity: `LicenseToken` (ERC-1155 entitlement) and `AppManifest` (per-app version records and developer-controlled upgrade economics).

**Language:** Solidity / Foundry
**Phase:** 1b of the [implementation plan](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md)

---

## Read before contributing

Every constraint that makes Verity work lives in
**[verity-foundation](https://github.com/ithaka-dev/verity-foundation)** — the specification, the
architecture decisions, the invariants, and the measured facts they rest on. This repository holds
an implementation of decisions made there, not the decisions themselves.

- [Specification](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — start here; §7 holds the invariants
- [Decisions (ADRs)](https://github.com/ithaka-dev/verity-foundation/tree/main/docs/decisions) — why things are the way they are
- [`CLAUDE.md`](CLAUDE.md) — what binds *this* repository specifically

**If a decision seems missing, it probably isn't — go and find it.** If it genuinely is missing,
it belongs in an ADR in `verity-foundation`, not in a pull request here.

## Boundary

Deployed contracts are effectively immutable, so [ADR 0005](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0005-design-for-smart-accounts-implement-eoa.md) binds hardest here.

- **Never call `ecrecover` directly.** All signature verification routes through a helper that dispatches to ERC-1271 and ERC-6492; the smart-account branch rejects explicitly rather than falling through to an EOA assumption.
- **App identity *is* the `AppManifest` address** ([ADR 0011](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0011-app-identity-is-manifest-address.md)). There is no registry — deploying a manifest *is* publishing an app, so the no-gatekeeper property holds structurally.
- Version entries are **append-only**, developer-writer-only (I5).
