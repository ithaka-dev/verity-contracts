// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../src/AppManifest.sol";
import {AppManifestFactory} from "../src/AppManifestFactory.sol";
import {LicenseToken} from "../src/LicenseToken.sol";
import {Test} from "forge-std/Test.sol";

contract AppManifestFactoryTest is Test {
    AppManifestFactory internal factory;

    ///  A hashed salt rather than a `bytes32("app")` literal: the string-to-bytes32 cast
    /// truncates silently past 32 bytes, and it is not worth teaching that pattern here.
    bytes32 internal constant SALT = keccak256("app");

    address internal developer = address(0xDE7);
    address internal outsider = address(0x0475);

    function setUp() public {
        factory = new AppManifestFactory();
    }

    // — it works —

    function test_deploysAManifestOwnedByTheNamedDeveloper() public {
        vm.prank(developer);
        address manifest = factory.deploy(SALT, developer);
        assertEq(AppManifest(manifest).developer(), developer);
        assertEq(AppManifest(manifest).mintAuthorizer(), developer);
    }

    function test_addressIsPredictable() public {
        address predicted = factory.predictAddress(developer, SALT, developer);
        vm.prank(developer);
        assertEq(factory.deploy(SALT, developer), predicted);
    }

    function testFuzz_predictionMatchesDeployment(bytes32 salt, address dev) public {
        vm.assume(dev != address(0));
        address predicted = factory.predictAddress(developer, salt, dev);
        vm.prank(developer);
        assertEq(factory.deploy(salt, dev), predicted);
    }

    /// Without caller-namespaced salts, a bystander could occupy an address a developer published
    /// in advance and intended to use.
    function test_saltsAreNamespacedByCaller() public {
        vm.prank(developer);
        address mine = factory.deploy(SALT, developer);
        vm.prank(outsider);
        address theirs = factory.deploy(SALT, developer);
        assertTrue(mine != theirs);
    }

    // — it is powerless, which is the part that matters —

    /// ADR 0011 and spec §1: an app deployed without the factory must be indistinguishable from one
    /// deployed with it. If this ever fails, the factory has become a registration step.
    function test_directDeploymentIsIndistinguishable() public {
        vm.prank(developer);
        AppManifest viaFactory = AppManifest(factory.deploy(SALT, developer));
        AppManifest direct = new AppManifest(developer);

        assertEq(
            keccak256(address(viaFactory).code),
            keccak256(address(direct).code),
            "same deployed bytecode"
        );
        assertEq(viaFactory.developer(), direct.developer());
        assertEq(viaFactory.burnOnUpgrade(), direct.burnOnUpgrade());
    }

    /// A licence minted against a directly-deployed manifest must work exactly as one minted
    /// against a factory-deployed manifest — `LicenseToken` must have no notion of provenance.
    function test_licenseTokenDoesNotCareWhereAManifestCameFrom() public {
        LicenseToken token = new LicenseToken();
        uint256 authorizerKey = 0xA11CE;
        address authorizer = vm.addr(authorizerKey);

        vm.prank(developer);
        AppManifest viaFactory = AppManifest(factory.deploy(SALT, developer));
        AppManifest direct = new AppManifest(developer);

        for (uint256 i = 0; i < 2; i++) {
            AppManifest m = i == 0 ? viaFactory : direct;
            vm.startPrank(developer);
            m.publishVersion(
                "1.0.0", keccak256("img"), keccak256("cmp"), "ipfs://c", 0, bytes32(0), "ipfs://m"
            );
            m.setMintAuthorizer(authorizer);
            vm.stopPrank();

            LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
                manifest: address(m),
                fromLicenseId: 0,
                version: "1.0.0",
                to: outsider,
                burnExpected: false,
                nonce: 1,
                expiry: block.timestamp + 1 hours
            });
            (uint8 v, bytes32 r, bytes32 s) =
                vm.sign(authorizerKey, token.hashMintAuthorization(auth));
            uint256 licenseId = token.mint(auth, abi.encodePacked(r, s, v));

            assertEq(token.balanceOf(outsider, licenseId), 1);
        }
    }

    /// The factory holds no state, so there is nothing to gate with and nothing another contract
    /// could consult as an authority over which apps are real.
    ///
    /// @dev **The authoritative check for this is the `factory-holds-no-state` CI job**, which
    /// asserts `forge inspect AppManifestFactory storageLayout` is empty. Solidity cannot read a
    /// storage layout, so a test here can only sample slots — and an earlier version of this test
    /// did exactly that on a factory nothing had been deployed through, which passes for any
    /// contract whatsoever and would not have noticed the `mapping(address => bool) deployedByUs`
    /// that ADR 0021 names as the thing to prevent. A mapping's entries live at
    /// `keccak256(key, slot)`, so slot 0 stays zero either way.
    ///
    /// This version at least deploys first, so a plain counter or a "last deployed" pointer shows
    /// up. Treat it as a smoke test; the CI job is the guarantee.
    function test_factoryHoldsNoStateAfterDeploying() public {
        vm.prank(developer);
        factory.deploy(SALT, developer);
        vm.prank(outsider);
        factory.deploy(keccak256("second"), outsider);

        for (uint256 slot = 0; slot < 8; slot++) {
            assertEq(vm.load(address(factory), bytes32(slot)), bytes32(0), "factory wrote a slot");
        }
    }

    /// Anyone may deploy a manifest for any developer. That reads like a missing check and is the
    /// property: deployment grants nothing — only the named developer can ever publish — so a
    /// permission here would be a gate with no corresponding power.
    function test_anyoneMayDeployForAnyDeveloper() public {
        vm.prank(outsider);
        AppManifest manifest = AppManifest(factory.deploy(SALT, developer));
        assertEq(manifest.developer(), developer);

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.NotDeveloper.selector, outsider));
        manifest.publishVersion(
            "1.0.0", keccak256("img"), keccak256("cmp"), "ipfs://c", 0, bytes32(0), "ipfs://m"
        );
    }
}
