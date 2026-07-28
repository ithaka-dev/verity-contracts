// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../src/AppManifest.sol";
import {IAppManifest} from "../src/IAppManifest.sol";
import {LicenseToken} from "../src/LicenseToken.sol";
import {SignatureChecker} from "../src/SignatureChecker.sol";
import {Test} from "forge-std/Test.sol";

/// @dev A contract account, used to prove the smart-account branch rejects explicitly rather than
/// failing as a bad signature.
contract ContractAccount {}

contract LicenseTokenTest is Test {
    LicenseToken internal token;
    AppManifest internal manifest;

    uint256 internal authorizerKey = 0xA11CE;
    address internal authorizer;
    address internal developer = address(0xDE7);
    address internal holder = address(0x40D3);
    address internal relayer = address(0x4E1A);

    bytes32 internal constant IMAGE_DIGEST = keccak256("image");
    bytes32 internal constant COMPOSE_V1 = keccak256("compose-1.0.0");
    bytes32 internal constant COMPOSE_V2 = keccak256("compose-2.0.0");

    function setUp() public {
        authorizer = vm.addr(authorizerKey);
        token = new LicenseToken();
        manifest = new AppManifest(developer);

        vm.startPrank(developer);
        manifest.publishVersion(
            "1.0.0", IMAGE_DIGEST, COMPOSE_V1, "ipfs://compose-1", 0, bytes32(0), "ipfs://meta-1"
        );
        manifest.publishVersion(
            "2.0.0", IMAGE_DIGEST, COMPOSE_V2, "ipfs://compose-2", 0, bytes32(0), "ipfs://meta-2"
        );
        manifest.setMintAuthorizer(authorizer);
        vm.stopPrank();
    }

    // — helpers —

    function _auth(string memory version, address to, uint256 nonce)
        internal
        view
        returns (LicenseToken.MintAuthorization memory)
    {
        return LicenseToken.MintAuthorization({
            manifest: address(manifest),
            version: version,
            to: to,
            nonce: nonce,
            expiry: block.timestamp + 1 hours
        });
    }

    function _sign(LicenseToken.MintAuthorization memory auth, uint256 key)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, token.hashMintAuthorization(auth));
        return abi.encodePacked(r, s, v);
    }

    function _mint(string memory version, address to, uint256 nonce) internal {
        LicenseToken.MintAuthorization memory auth = _auth(version, to, nonce);
        token.mint(auth, _sign(auth, authorizerKey));
    }

    function _allowTransition(string memory from, string memory to) internal {
        vm.prank(developer);
        manifest.setUpgradePrice(from, to, 1 ether, true);
    }

    // — C-08: the tokenId scheme —

    /// The property that makes "no registry" true: a tokenId is computable by anyone, offline,
    /// from an address and a string. Nothing has to be written anywhere first.
    function test_tokenIdIsPureDerivation() public view {
        assertEq(
            token.tokenIdFor(address(manifest), "1.0.0"),
            uint256(keccak256(abi.encode(address(manifest), keccak256(bytes("1.0.0")))))
        );
    }

    function test_tokenIdDiffersByVersionAndByApp() public {
        AppManifest other = new AppManifest(developer);
        assertTrue(
            token.tokenIdFor(address(manifest), "1.0.0")
                != token.tokenIdFor(address(manifest), "2.0.0")
        );
        assertTrue(
            token.tokenIdFor(address(manifest), "1.0.0") != token.tokenIdFor(address(other), "1.0.0")
        );
    }

    /// `abi.encode` rather than `encodePacked`: two apps whose (address, version) pairs concatenate
    /// identically must still get different ids. A collision here would let one app's licence
    /// entitle a holder to run another's.
    function test_adjacentVersionStringsDoNotCollide() public view {
        assertTrue(
            token.tokenIdFor(address(manifest), "1.0") != token.tokenIdFor(address(manifest), "10")
        );
    }

    function testFuzz_tokenIdIsDeterministic(address app, string calldata version) public view {
        assertEq(token.tokenIdFor(app, version), token.tokenIdFor(app, version));
    }

    // — C-10: mint authorization —

    function test_mintWithValidAuthorization() public {
        _mint("1.0.0", holder, 1);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 1);
    }

    /// Nothing of the recipient's is consumed by a mint, so a relayer paying gas is legitimate.
    function test_anyoneMaySubmitAMint() public {
        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(relayer);
        token.mint(auth, signature);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 1);
    }

    function test_mintRejectsWrongSigner() public {
        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 1);
        bytes memory signature = _sign(auth, 0xBAD);
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        token.mint(auth, signature);
    }

    /// Authority is read out of the app's own manifest. A developer who has not delegated is still
    /// the only valid signer, so a payment service cannot mint for an app that never appointed it.
    function test_mintRejectsAuthorizerOfAnotherApp() public {
        AppManifest other = new AppManifest(developer);
        vm.prank(developer);
        other.publishVersion(
            "1.0.0", IMAGE_DIGEST, COMPOSE_V1, "ipfs://compose-1", 0, bytes32(0), "ipfs://meta-1"
        );

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(other),
            version: "1.0.0",
            to: holder,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });
        // Signed by this app's authorizer, submitted against an app that never appointed them.
        bytes memory signature = _sign(auth, authorizerKey);
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        token.mint(auth, signature);
    }

    function test_mintRejectsExpiredAuthorization() public {
        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.warp(auth.expiry + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.AuthorizationExpired.selector, auth.expiry, block.timestamp
            )
        );
        token.mint(auth, signature);
    }

    function test_mintRejectsNonceReplay() public {
        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 7);
        bytes memory signature = _sign(auth, authorizerKey);
        token.mint(auth, signature);
        assertTrue(token.nonceUsed(address(manifest), 7));

        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.NonceAlreadyUsed.selector, address(manifest), uint256(7)
            )
        );
        token.mint(auth, signature);
    }

    /// Nonces are arbitrary rather than sequential, so a payment service can issue authorizations
    /// concurrently without serialising them behind a counter.
    function test_noncesNeedNoOrdering() public {
        _mint("1.0.0", holder, 99);
        _mint("1.0.0", holder, 2);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 2);
    }

    /// A licence cannot exist for a version that was never published — the manifest is asked, and it
    /// reverts.
    function test_mintRejectsUnpublishedVersion() public {
        LicenseToken.MintAuthorization memory auth = _auth("9.9.9", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.expectRevert(abi.encodeWithSelector(AppManifest.UnknownVersion.selector, "9.9.9"));
        token.mint(auth, signature);
    }

    /// ADR 0005: the smart-account branch says "not supported", not "invalid signature". Those are
    /// different problems and only one of them is the caller's.
    function test_contractAuthorizerIsRejectedExplicitly() public {
        address contractAuthorizer = address(new ContractAccount());
        vm.prank(developer);
        manifest.setMintAuthorizer(contractAuthorizer);

        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureChecker.SmartAccountNotSupportedInMvp.selector, contractAuthorizer
            )
        );
        token.mint(auth, signature);
    }

    // — C-09: uri() resolves through to the manifest —

    function test_uriResolvesThroughToManifestMetadata() public {
        _mint("1.0.0", holder, 1);
        assertEq(token.uri(token.tokenIdFor(address(manifest), "1.0.0")), "ipfs://meta-1");
    }

    function test_uriRevertsForATokenNeverMinted() public {
        uint256 tokenId = token.tokenIdFor(address(manifest), "2.0.0");
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownToken.selector, tokenId));
        token.uri(tokenId);
    }

    function test_originRecordsTheDerivation() public {
        _mint("1.0.0", holder, 1);
        LicenseToken.TokenOrigin memory origin =
            token.originOf(token.tokenIdFor(address(manifest), "1.0.0"));
        assertEq(origin.manifest, address(manifest));
        assertEq(origin.version, "1.0.0");
    }

    // — C-07: atomic burn + mint —

    function test_upgradeBurnsOldAndMintsNewInOneTransaction() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade("1.0.0", auth, signature);

        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 0);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "2.0.0")), 1);
    }

    /// ADR 0008: there is no two-instance window, so §2.9 needs no exemption. Asserted by checking
    /// the holder never holds both — which, since it is one transaction, is checked by the totals.
    function test_upgradeLeavesExactlyOneLicence() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade("1.0.0", auth, signature);

        uint256 total = token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0"))
            + token.balanceOf(holder, token.tokenIdFor(address(manifest), "2.0.0"));
        assertEq(total, 1);
    }

    /// The developer's opt-out. Not burning grants an extra runnable instance under §2.9 — the
    /// consequence the developer surface has to state where the knob is set.
    function test_notBurningGrantsAnAdditionalInstance() public {
        vm.prank(developer);
        manifest.setBurnOnUpgrade(false);

        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade("1.0.0", auth, signature);

        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 1);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "2.0.0")), 1);
    }

    /// Doing nothing keeps a holder on the digest they licensed, indefinitely (ADR 0003). A
    /// transition the developer has not priced as permitted does not happen.
    function test_upgradeRequiresAPricedTransition() public {
        _mint("1.0.0", holder, 1);
        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.TransitionNotAllowed.selector, "1.0.0", "2.0.0")
        );
        token.upgrade("1.0.0", auth, signature);
    }

    function test_upgradeRequiresHoldingTheSourceVersion() public {
        _allowTransition("1.0.0", "2.0.0");
        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        // Resolved before the prank: `tokenIdFor` is an external call, and it would otherwise be
        // the call the prank applies to.
        uint256 fromTokenId = token.tokenIdFor(address(manifest), "1.0.0");
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.NotAHolder.selector, fromTokenId));
        token.upgrade("1.0.0", auth, signature);
    }

    /// The authorization is the seller's consent to sell, never the holder's consent to give up
    /// what they hold. A relayer submitting it would supply only half of what a burn needs.
    function test_relayerCannotUpgradeOnAHoldersBehalf() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.RelayedUpgradeNotSupportedInMvp.selector, relayer, holder
            )
        );
        token.upgrade("1.0.0", auth, signature);
    }

    // — downgrades —

    function test_downgradeBlockedByDefault() public {
        _mint("2.0.0", holder, 1);
        _allowTransition("2.0.0", "1.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.DowngradesNotAllowed.selector, "2.0.0", "1.0.0")
        );
        token.upgrade("2.0.0", auth, signature);
    }

    /// Rollback is the developer's to define (ADR 0004). Note the holder gets the old *version*
    /// with *fresh* state — backward state migration is not realistic, and that belongs in the
    /// developer's documentation rather than in this contract.
    function test_downgradeAllowedWhenDeveloperPermitsIt() public {
        vm.prank(developer);
        manifest.setDowngradesAllowed(true);

        _mint("2.0.0", holder, 1);
        _allowTransition("2.0.0", "1.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade("2.0.0", auth, signature);

        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "1.0.0")), 1);
        assertEq(token.balanceOf(holder, token.tokenIdFor(address(manifest), "2.0.0")), 0);
    }

    /// Ordering comes from publication order, not from parsing the string — `"1.10.0"` sorts below
    /// `"1.9.0"` as text, and nothing obliges a developer to use semver at all.
    function test_versionOrderingIsPublicationOrderNotStringOrder() public {
        vm.prank(developer);
        manifest.publishVersion(
            "1.10.0", IMAGE_DIGEST, keccak256("c3"), "ipfs://c3", 0, bytes32(0), "ipfs://m3"
        );
        assertGt(manifest.versionIndex("1.10.0"), manifest.versionIndex("2.0.0"));
    }

    function test_upgradeToSameVersionIsRejected() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "1.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.SameVersion.selector, "1.0.0"));
        token.upgrade("1.0.0", auth, signature);
    }

    function test_upgradeRejectsNonceReplay() public {
        _mint("1.0.0", holder, 1);
        _mint("1.0.0", holder, 3);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade("1.0.0", auth, signature);

        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.NonceAlreadyUsed.selector, address(manifest), uint256(2)
            )
        );
        token.upgrade("1.0.0", auth, signature);
    }
}
