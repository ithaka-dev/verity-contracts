# Vendored dependencies

Committed in full rather than referenced as submodules, so a fresh clone builds with no extra
step and the exact bytes under test are the exact bytes in the repository.

| Dependency | Version | Source |
|---|---|---|
| `forge-std` | 1.16.2 | https://github.com/foundry-rs/forge-std |

**Recording the version is the point.** A dependency present at no stated version is a copy of
something, not a pin — the same defect [ADR 0007](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0007-compose-must-pin-digests.md)
identifies for container images, in a different package manager.

Updating one is a deliberate commit that changes this table, not a background drift.
