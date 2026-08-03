// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../src/AppManifest.sol";
import {IAppManifest} from "../src/IAppManifest.sol";
import {Test} from "forge-std/Test.sol";

contract AppManifestTest is Test {
    AppManifest internal manifest;
    address internal dev = address(0xDE7);
    address internal stranger = address(0x57A);

    /// The configuration measured on real TDX hardware.
    bytes32 internal constant COMPOSE_HASH =
        0x64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd;
    bytes32 internal constant IMAGE_DIGEST =
        0xd9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc;

    function setUp() public {
        manifest = new AppManifest(dev);
    }

    function _publish(string memory version, bytes32 composeHash) internal {
        vm.prank(dev);
        manifest.publishVersion(
            version, IMAGE_DIGEST, composeHash, "ipfs://bafk...", 0, bytes32(0), ""
        );
    }

    // — identity —

    /// ADR 0011: the contract's address is the app's identity. There is no registry to gate, which
    /// is what makes §1's no-gatekeeper property structural rather than a policy.
    function test_hasNoRegistrationOrOwnerBeyondTheDeveloper() public view {
        assertEq(manifest.developer(), dev);
    }

    // — I5: append-only —

    function test_publishesAVersion() public {
        _publish("1.0.0", COMPOSE_HASH);
        IAppManifest.VersionRecord memory r = manifest.versionRecord("1.0.0");
        assertEq(r.composeHash, COMPOSE_HASH);
        assertEq(r.imageDigest, IMAGE_DIGEST);
        assertTrue(r.exists);
    }

    /// A developer must not be able to change what a version means after someone licensed it.
    /// Without this, a licence naming "1.0.0" would name whatever 1.0.0 currently is.
    function test_cannotOverwriteAPublishedVersion() public {
        _publish("1.0.0", COMPOSE_HASH);
        vm.prank(dev);
        vm.expectRevert(
            abi.encodeWithSelector(AppManifest.VersionAlreadyPublished.selector, "1.0.0")
        );
        manifest.publishVersion(
            "1.0.0", IMAGE_DIGEST, keccak256("different"), "ipfs://other", 0, bytes32(0), ""
        );
    }

    function test_onlyDeveloperMayPublish() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, stranger));
        manifest.publishVersion(
            "1.0.0", IMAGE_DIGEST, COMPOSE_HASH, "ipfs://bafk", 0, bytes32(0), ""
        );
    }

    /// A record without an imageDigest would leave the verifier's cross-check with nothing to
    /// compare — and that check is the only digest-pinning enforcement an attacker cannot route
    /// around (ADR 0007).
    function test_rejectsRecordsMissingWhatVerificationNeeds() public {
        vm.startPrank(dev);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "composeHash"));
        manifest.publishVersion("a", IMAGE_DIGEST, bytes32(0), "ipfs://x", 0, bytes32(0), "");

        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "imageDigest"));
        manifest.publishVersion("b", bytes32(0), COMPOSE_HASH, "ipfs://x", 0, bytes32(0), "");

        // Without a retrievable compose a verifier cannot compute the expected measurement at all.
        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "composeURI"));
        manifest.publishVersion("c", IMAGE_DIGEST, COMPOSE_HASH, "", 0, bytes32(0), "");
        vm.stopPrank();
    }

    function test_unknownVersionReverts() public {
        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "9.9.9"));
        manifest.versionRecord("9.9.9");
        assertFalse(manifest.versionExists("9.9.9"));
    }

    // — knob 1: pricing —

    function test_pricingIsDirectional() public {
        _publish("1.0.0", COMPOSE_HASH);
        _publish("2.0.0", keccak256("v2"));

        vm.prank(dev);
        manifest.setUpgradePrice("1.0.0", "2.0.0", 1 ether, true);

        (uint256 price, bool allowed) = manifest.upgradePrice("1.0.0", "2.0.0");
        assertEq(price, 1 ether);
        assertTrue(allowed);

        // The reverse transition is a different thing and is not implied.
        (uint256 backPrice, bool backAllowed) = manifest.upgradePrice("2.0.0", "1.0.0");
        assertEq(backPrice, 0);
        assertFalse(backAllowed, "a downgrade is not implied by pricing the upgrade");
    }

    /// Free and forbidden are different, so `allowed` is separate from a zero price. Conflating
    /// them would make every unpriced transition free rather than refused.
    function test_freeIsNotTheSameAsForbidden() public {
        _publish("1.0.0", COMPOSE_HASH);
        _publish("1.1.0", keccak256("v11"));

        vm.prank(dev);
        manifest.setUpgradePrice("1.0.0", "1.1.0", 0, true);

        (uint256 price, bool allowed) = manifest.upgradePrice("1.0.0", "1.1.0");
        assertEq(price, 0);
        assertTrue(allowed, "a free upgrade is permitted, not merely unpriced");
    }

    function test_cannotPriceUnknownVersions() public {
        _publish("1.0.0", COMPOSE_HASH);
        vm.prank(dev);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "2.0.0"));
        manifest.setUpgradePrice("1.0.0", "2.0.0", 1, true);
    }

    // — knob 2: burn —

    /// Burn defaults to true. Not burning grants an additional runnable instance under §2.9, so a
    /// developer giving away free minor versions without burning gives away concurrency.
    function test_burnDefaultsToTrue() public view {
        assertTrue(manifest.burnOnUpgrade());
    }

    function test_developerMayOptOutOfBurning() public {
        vm.prank(dev);
        manifest.setBurnOnUpgrade(false);
        assertFalse(manifest.burnOnUpgrade());
    }

    /// @dev The most powerful privilege in the system, and it was covered by nothing: deleting
    /// `onlyDeveloper` from `setMintAuthorizer` survived the entire suite. Anyone could then point
    /// any app's authorizer at themselves, sign their own authorizations, and mint unlimited
    /// licences for every published version — no payment, no developer involvement, and no patch
    /// available afterwards.
    function test_onlyDeveloperMaySetMintAuthorizer() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, stranger));
        manifest.setMintAuthorizer(stranger);

        assertEq(manifest.mintAuthorizer(), dev, "authorizer must be unchanged");
    }

    /// One of the developer's two ADR 0004 knobs. Anyone able to call this could mark arbitrary
    /// transitions permitted.
    function test_onlyDeveloperMaySetUpgradePrice() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, stranger));
        manifest.setUpgradePrice("1.0.0", "2.0.0", 0, true);

        (, bool allowed) = manifest.upgradePrice("1.0.0", "2.0.0");
        assertFalse(allowed, "transition must remain forbidden");
    }

    function test_onlyDeveloperMaySetKnobs() public {
        vm.startPrank(stranger);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, stranger));
        manifest.setBurnOnUpgrade(false);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, stranger));
        manifest.setDowngradesAllowed(true);
        vm.stopPrank();
    }

    // — knob 3: downgrades —

    function test_downgradesAreOffByDefault() public view {
        assertFalse(manifest.downgradesAllowed());
    }

    function test_developerMayPermitDowngrades() public {
        vm.prank(dev);
        manifest.setDowngradesAllowed(true);
        assertTrue(manifest.downgradesAllowed());
    }

    // — capabilities are a bitmap, not a tier —

    /// Capabilities have no natural ordering: an app may implement `migrate` without `health`.
    /// A tier would imply a hierarchy that does not exist.
    function test_capabilitiesAreIndependentBits() public {
        uint256 migrateOnly = manifest.CAPABILITY_MIGRATE();
        _publishWithCapabilities("1.0.0", migrateOnly);

        assertTrue(manifest.hasCapability("1.0.0", manifest.CAPABILITY_MIGRATE()));
        assertFalse(
            manifest.hasCapability("1.0.0", manifest.CAPABILITY_HEALTH()),
            "migrate must not imply health"
        );
        assertFalse(manifest.hasCapability("1.0.0", manifest.CAPABILITY_EXPORT()));
    }

    function test_capabilitiesCombine() public {
        uint256 all = manifest.CAPABILITY_HEALTH() | manifest.CAPABILITY_MIGRATE()
            | manifest.CAPABILITY_EXPORT();
        _publishWithCapabilities("2.0.0", all);
        assertTrue(manifest.hasCapability("2.0.0", manifest.CAPABILITY_HEALTH()));
        assertTrue(manifest.hasCapability("2.0.0", manifest.CAPABILITY_MIGRATE()));
        assertTrue(manifest.hasCapability("2.0.0", manifest.CAPABILITY_EXPORT()));
    }

    /// Bits must not overlap, or declaring one capability would silently declare another.
    function test_capabilityBitsAreDistinct() public view {
        uint256 h = manifest.CAPABILITY_HEALTH();
        uint256 m = manifest.CAPABILITY_MIGRATE();
        uint256 e = manifest.CAPABILITY_EXPORT();
        assertEq(h & m, 0);
        assertEq(h & e, 0);
        assertEq(m & e, 0);
    }

    function _publishWithCapabilities(string memory version, uint256 capabilities) internal {
        vm.prank(dev);
        manifest.publishVersion(
            version,
            IMAGE_DIGEST,
            keccak256(bytes(version)),
            "ipfs://bafk",
            capabilities,
            bytes32(0),
            ""
        );
    }

    // — fuzz —

    function testFuzz_anyPublishedVersionIsRetrievable(bytes32 composeHash, bytes32 imageDigest)
        public
    {
        vm.assume(composeHash != bytes32(0) && imageDigest != bytes32(0));
        vm.prank(dev);
        manifest.publishVersion("v", imageDigest, composeHash, "ipfs://x", 0, bytes32(0), "");
        IAppManifest.VersionRecord memory r = manifest.versionRecord("v");
        assertEq(r.composeHash, composeHash);
        assertEq(r.imageDigest, imageDigest);
    }

    function testFuzz_nonDeveloperNeverWrites(address caller) public {
        vm.assume(caller != dev);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, caller));
        manifest.publishVersion("x", IMAGE_DIGEST, COMPOSE_HASH, "ipfs://x", 0, bytes32(0), "");
    }

    // — T-08: the refusals nothing had exercised —
    //
    // Every one of these is a `revert` that had never executed. A guard no test runs is
    // indistinguishable from a guard that does not work, and these are the guards that decide
    // whether a *malformed* manifest can exist at all — a version with no name, an app with no
    // developer, a price quoted for a version that was never published. Each one, unenforced,
    // produces a record that reads as valid and binds to nothing.

    /// An app with no developer has no one who can publish to it, so it is a manifest that can
    /// never hold a version — and under ADR 0011 the manifest address *is* the app's identity, so
    /// this would mint an identity for an app that cannot exist.
    function test_refusesAManifestWithNoDeveloper() public {
        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "developer"));
        new AppManifest(address(0));
    }

    /// Zero here does not disable minting, it makes `LicenseToken` compare a recovered signer
    /// against `address(0)` — and `ecrecover` returns `address(0)` for a malformed signature. The
    /// two would meet, and garbage would authorize a mint.
    function test_refusesAZeroMintAuthorizer() public {
        vm.prank(dev);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "mintAuthorizer"));
        manifest.setMintAuthorizer(address(0));
    }

    /// The empty string is a valid mapping key, so an unnamed version would publish successfully
    /// and then be unaddressable by anything a holder could type.
    function test_refusesAVersionWithNoName() public {
        vm.prank(dev);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.EmptyField.selector, "version"));
        manifest.publishVersion("", IMAGE_DIGEST, COMPOSE_HASH, "ipfs://x", 0, bytes32(0), "");
    }

    /// Both ends, because a price is a claim about a transition and a transition needs two real
    /// endpoints. Priced against a version that does not exist, it is a transition no holder can
    /// ever take — and worse, it would start working the day someone published that name.
    function test_refusesAPriceForAnUnpublishedVersion() public {
        _publish("1.0.0", COMPOSE_HASH);

        vm.startPrank(dev);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "0.9.0"));
        manifest.setUpgradePrice("0.9.0", "1.0.0", 1 ether, true);

        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "2.0.0"));
        manifest.setUpgradePrice("1.0.0", "2.0.0", 1 ether, true);
        vm.stopPrank();
    }

    /// Refuses rather than answering `false`. "This version declares no capabilities" and "there is
    /// no such version" are different facts, and a caller that cannot tell them apart will treat a
    /// typo'd version as an app that simply does not implement `migrate`.
    function test_capabilityQueryRefusesAnUnknownVersionRatherThanSayingNo() public {
        _publish("1.0.0", COMPOSE_HASH);
        uint256 migrate = manifest.CAPABILITY_MIGRATE();
        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "9.9.9"));
        manifest.hasCapability("9.9.9", migrate);
    }

    /// `versionCount` is what makes publication order observable off-chain, and I5 makes it
    /// monotonic. Downgrade detection reads the same counter.
    function test_versionCountTracksPublication() public {
        assertEq(manifest.versionCount(), 0);
        _publish("1.0.0", COMPOSE_HASH);
        assertEq(manifest.versionCount(), 1);
        _publish("2.0.0", keccak256("compose-2"));
        assertEq(manifest.versionCount(), 2);
        assertEq(manifest.versionIndex("2.0.0"), 2, "index is the 1-based publication order");
    }
}
