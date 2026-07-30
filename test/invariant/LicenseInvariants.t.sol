// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../../src/AppManifest.sol";
import {IAppManifest} from "../../src/IAppManifest.sol";
import {LicenseToken} from "../../src/LicenseToken.sol";
import {LicenseHandler} from "./LicenseHandler.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

/// @title LicenseInvariants
/// @notice Properties that must hold after **any** sequence of publishing, minting, upgrading and
/// transferring — not just the sequences someone thought to write a unit test for.
///
/// @dev The unit tests check that each operation does the right thing. These check that no
/// combination of them can reach a state that should not exist, which is a different question and
/// the one that matters for a contract nobody can patch.
contract LicenseInvariants is Test {
    LicenseToken internal token;
    LicenseHandler internal handler;

    address internal developer = address(0xDE7);

    function setUp() public {
        token = new LicenseToken();
        handler = new LicenseHandler(token, developer, 2);
        targetContract(address(handler));
    }

    /// I5. A published version record is immutable. A developer must not be able to change what a
    /// version means after someone has licensed it — otherwise a holder's `composeHash` binding
    /// points at something the developer can redefine, and the defining property
    /// `licensed_composeHash == attested_composeHash` becomes a statement about a moving target.
    function invariant_versionRecordsNeverChange() public view {
        for (uint256 mi = 0; mi < handler.manifestCount(); mi++) {
            AppManifest m = handler.manifests(mi);
            uint256 count = handler.publishedCount(mi);
            for (uint256 i = 0; i < count; i++) {
                string memory version = handler.publishedAt(mi, i);
                bytes32 key = handler.versionKey(mi, version);
                IAppManifest.VersionRecord memory record = m.versionRecord(version);

                assertEq(
                    record.composeHash, handler.publishedComposeHash(key), "composeHash changed"
                );
                assertEq(
                    record.imageDigest, handler.publishedImageDigest(key), "imageDigest changed"
                );
                assertEq(record.composeURI, handler.publishedComposeURI(key), "composeURI changed");
                assertEq(record.index, i + 1, "publication order changed");
            }
        }
    }

    /// Publication order is strictly increasing and gapless, which is what makes "is this a
    /// downgrade?" answerable on chain without parsing version strings.
    function invariant_publicationOrderIsMonotonic() public view {
        for (uint256 mi = 0; mi < handler.manifestCount(); mi++) {
            AppManifest m = handler.manifests(mi);
            assertEq(m.versionCount(), handler.publishedCount(mi), "version count drifted");
            for (uint256 i = 0; i < handler.publishedCount(mi); i++) {
                assertEq(m.versionIndex(handler.publishedAt(mi, i)), i + 1);
            }
        }
    }

    /// Supply is conserved: every licence in existence came from a mint, and every one that
    /// vanished was burned by an upgrade. A licence cannot appear from anywhere else, and a
    /// transfer moves one without creating or destroying it.
    function invariant_supplyEqualsMintsMinusBurns() public view {
        for (uint256 i = 0; i < handler.issuedCount(); i++) {
            uint256 licenseId = handler.issued(i);

            uint256 held;
            for (uint256 a = 0; a < handler.actorCount(); a++) {
                held += token.balanceOf(handler.actors(a), licenseId);
            }

            assertEq(
                held,
                handler.ghostMinted(licenseId) - handler.ghostBurned(licenseId),
                "supply is not mints minus burns"
            );
        }
    }

    /// **Every licence is one indivisible unit** (ADR 0023). A balance above 1 would restore the
    /// fungibility that made `balanceOf(holder, id)` a membership question rather than an ownership
    /// one — the defect that let any holder of a version act on any other holder's instance.
    function invariant_everyLicenceIsExactlyOneUnit() public view {
        for (uint256 i = 0; i < handler.issuedCount(); i++) {
            uint256 licenseId = handler.issued(i);
            for (uint256 a = 0; a < handler.actorCount(); a++) {
                assertLe(token.balanceOf(handler.actors(a), licenseId), 1, "a licence is one unit");
            }
        }
    }

    /// An instance is claimed by at most one licence, ever. Two licences claiming one instance
    /// would mean two holders able to act on it, which is the defect this binding closes.
    function invariant_noInstanceIsClaimedTwice() public view {
        for (uint256 i = 0; i < handler.issuedCount(); i++) {
            bytes32 instanceId = token.instanceOf(handler.issued(i));
            if (instanceId == bytes32(0)) continue;
            uint256 claimant = token.claimedBy(instanceId);
            assertTrue(claimant != 0, "a bound instance must have a claimant");

            for (uint256 j = 0; j < handler.issuedCount(); j++) {
                if (i == j) continue;
                if (token.instanceOf(handler.issued(j)) == instanceId) {
                    assertEq(
                        handler.issued(i),
                        handler.issued(j),
                        "two different licences point at one instance"
                    );
                }
            }
        }
    }

    /// No two licences share an id, so ownership of one is never ownership of another.
    function invariant_licenceIdsAreUnique() public view {
        for (uint256 i = 0; i < handler.issuedCount(); i++) {
            for (uint256 j = i + 1; j < handler.issuedCount(); j++) {
                assertTrue(handler.issued(i) != handler.issued(j), "two licences share an id");
            }
        }
    }

    /// ADR 0008: burn and mint happen in one transaction, so an upgrade under `burnOnUpgrade` never
    /// changes how many licences a holder has for that app. No two-instance window means spec §2.9
    /// needs no exemption for upgrades — and no window with neither means a holder cannot be left
    /// with nothing.
    function invariant_upgradeIsAtomic() public view {
        assertFalse(handler.atomicityViolated(), "an upgrade changed a holder's total unexpectedly");
    }

    /// **The invariant that earns this suite its place.**
    ///
    /// Conservation properties are blind to authorization: a licence minted by an attacker is
    /// conserved exactly as carefully as one minted legitimately. Every bug this contract has
    /// actually shipped was an authorization bug, so a suite built only from conservation
    /// properties could not have caught any of them — measured, not assumed: an earlier version of
    /// this file survived the deletion of `requireValidSignature` from `LicenseToken`.
    ///
    /// `tryGuards` attempts each forbidden operation against whatever state the fuzzer has reached.
    /// The failure message names which guard fell.
    function invariant_noGuardWasEverBypassed() public view {
        assertFalse(handler.guardBypassed(), handler.bypassDetail());
    }

    /// A collision would let one app's licence entitle a holder to run another's, which no
    /// conservation property notices — the balances stay perfectly consistent.
    function invariant_allVersionIdsAreDistinct() public view {
        uint256[] memory seen = new uint256[](_totalPublished());
        uint256 n = 0;
        for (uint256 mi = 0; mi < handler.manifestCount(); mi++) {
            address m = address(handler.manifests(mi));
            for (uint256 i = 0; i < handler.publishedCount(mi); i++) {
                uint256 versionId = token.versionIdFor(m, handler.publishedAt(mi, i));
                for (uint256 j = 0; j < n; j++) {
                    assertTrue(seen[j] != versionId, "two (app, version) pairs share an id");
                }
                seen[n++] = versionId;
            }
        }
    }

    function _totalPublished() internal view returns (uint256 total) {
        for (uint256 mi = 0; mi < handler.manifestCount(); mi++) {
            total += handler.publishedCount(mi);
        }
    }

    /// Every minted licence round-trips: its origin names the app it was minted against, and `uri`
    /// resolves through to that version's metadata.
    ///
    /// @dev Deliberately **not** claiming "no licence exists for an unpublished version" — this
    /// loop iterates the published set, so an unpublished-version licence is outside its domain by
    /// construction and it could never observe one. That property is checked where it can actually
    /// fail, by `_guardUnpublishedVersionCannotMint` in the handler.
    function invariant_everyLicenceResolvesToAPublishedVersion() public view {
        for (uint256 mi = 0; mi < handler.manifestCount(); mi++) {
            AppManifest m = handler.manifests(mi);
            for (uint256 i = 0; i < handler.publishedCount(mi); i++) {
                string memory version = handler.publishedAt(mi, i);
                assertTrue(m.versionExists(version));
            }
        }
        for (uint256 i = 0; i < handler.issuedCount(); i++) {
            uint256 licenseId = handler.issued(i);
            LicenseToken.TokenOrigin memory origin = token.originOf(licenseId);
            AppManifest m = AppManifest(origin.manifest);
            assertTrue(m.versionExists(origin.version), "origin names an unpublished version");
            assertEq(token.uri(licenseId), m.versionRecord(origin.version).metadataURI);
        }
    }

    /// A run in which nothing succeeded proves nothing while reporting a pass. This is the guard
    /// against a silently vacuous invariant suite.
    ///
    /// @dev It lives in `afterInvariant` rather than as an `invariant_` because invariants are also
    /// evaluated immediately after `setUp`, when the counters are legitimately zero — as an
    /// `invariant_` it fails every run before the fuzzer has done anything.
    function afterInvariant() public view {
        console2.log("publishes", handler.publishCount());
        console2.log("mints    ", handler.mintCount());
        console2.log("upgrades ", handler.upgradeCount());
        console2.log("guard runs", handler.guardAttempts());

        assertGt(handler.publishCount(), 0, "no version was ever published");
        assertGt(handler.mintCount(), 0, "no licence was ever minted");
        assertGt(handler.upgradeCount(), 0, "no upgrade was ever performed");
        // Without this the authorization guarantees are unproven, however green the run looks.
        assertGt(handler.guardAttempts(), 0, "no forbidden operation was ever attempted");
    }
}
