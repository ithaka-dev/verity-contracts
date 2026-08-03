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

/// @dev A manifest that answers, but lies.
///
/// `auth.manifest` is supplied by whoever submits the authorization, so `LicenseToken` is talking
/// to an address of the caller's choosing — nothing obliges it to be an `AppManifest`. Every guard
/// downstream of that call has to hold against a contract built to defeat it, and the only way to
/// know one does is to build that contract.
///
/// This one issues a version record freely, so a licence can be minted against it, then reports
/// publication index 0 — the value a real manifest uses to mean "no such version". A licence whose
/// own manifest disowns its version is the state that reaches the `fromIndex == 0` guard.
contract LyingManifest {
    address public developer;
    address public mintAuthorizer;
    bool public burnOnUpgrade;
    bool public downgradesAllowed = true;

    constructor(address authorizer_) {
        developer = msg.sender;
        mintAuthorizer = authorizer_;
    }

    function versionRecord(string calldata)
        external
        pure
        returns (IAppManifest.VersionRecord memory)
    {
        return IAppManifest.VersionRecord({
            imageDigest: keccak256("image"),
            composeHash: keccak256("compose"),
            composeURI: "ipfs://whatever",
            capabilities: 0,
            metadataHash: bytes32(0),
            metadataURI: "",
            index: 0,
            exists: true
        });
    }

    /// The lie. A real manifest returns 0 only for a version it has never published.
    function versionIndex(string calldata) external pure returns (uint256) {
        return 0;
    }

    function upgradePrice(string calldata, string calldata) external pure returns (uint256, bool) {
        return (0, true);
    }
}

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
        return _auth(0, version, to, nonce);
    }

    function _auth(uint256 fromLicenseId, string memory version, address to, uint256 nonce)
        internal
        view
        returns (LicenseToken.MintAuthorization memory)
    {
        // Signed with whatever the manifest currently says, which is what an honest payment
        // service would do at the moment it charged.
        return LicenseToken.MintAuthorization({
            manifest: address(manifest),
            fromLicenseId: fromLicenseId,
            version: version,
            to: to,
            burnExpected: manifest.burnOnUpgrade(),
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

    function _mint(string memory version, address to, uint256 nonce) internal returns (uint256) {
        LicenseToken.MintAuthorization memory auth = _auth(version, to, nonce);
        return token.mint(auth, _sign(auth, authorizerKey));
    }

    /// The `serial`-th licence minted for `version` of this app.
    function _lic(string memory version, uint256 serial) internal view returns (uint256) {
        return token.licenseIdFor(address(manifest), version, serial);
    }

    function _allowTransition(string memory from, string memory to) internal {
        vm.prank(developer);
        manifest.setUpgradePrice(from, to, 1 ether, true);
    }

    // — C-08: the tokenId scheme —

    /// The property that makes "no registry" true: a version id is computable by anyone, offline,
    /// from an address and a string. Nothing has to be written anywhere first.
    function test_versionIdIsPureDerivation() public view {
        assertEq(
            token.versionIdFor(address(manifest), "1.0.0"),
            uint256(keccak256(abi.encode(address(manifest), keccak256(bytes("1.0.0")))))
        );
    }

    /// **The property ADR 0023 exists for.** Two holders of the same version hold *different*
    /// licences, so `balanceOf(holder, licenseId)` asks who owns one specific entitlement. Under
    /// the previous per-version ids it asked only whether someone was a customer of that version —
    /// which let any holder of a version act on any other holder's instance.
    function test_eachLicenceIsADistinctUnit() public {
        uint256 first = _mint("1.0.0", holder, 1);
        uint256 second = _mint("1.0.0", relayer, 2);

        assertTrue(first != second, "two licences for one version must not share an id");
        assertEq(token.balanceOf(holder, first), 1);
        assertEq(token.balanceOf(holder, second), 0, "holder must not hold the other's licence");
        assertEq(token.balanceOf(relayer, second), 1);
        assertEq(token.balanceOf(relayer, first), 0);
    }

    function test_licenceIdsAreDerivableFromTheSerial() public {
        assertEq(_mint("1.0.0", holder, 1), _lic("1.0.0", 1));
        assertEq(_mint("1.0.0", holder, 2), _lic("1.0.0", 2));
        assertEq(token.mintedCount(address(manifest), "1.0.0"), 2);
    }

    function test_versionIdDiffersByVersionAndByApp() public {
        AppManifest other = new AppManifest(developer);
        assertTrue(
            token.versionIdFor(address(manifest), "1.0.0")
                != token.versionIdFor(address(manifest), "2.0.0")
        );
        assertTrue(
            token.versionIdFor(address(manifest), "1.0.0")
                != token.versionIdFor(address(other), "1.0.0")
        );
    }

    /// `abi.encode` rather than `encodePacked`: two apps whose (address, version) pairs concatenate
    /// identically must still get different ids. A collision here would let one app's licence
    /// entitle a holder to run another's.
    function test_adjacentVersionStringsDoNotCollide() public view {
        assertTrue(
            token.versionIdFor(address(manifest), "1.0")
                != token.versionIdFor(address(manifest), "10")
        );
    }

    function testFuzz_versionIdIsDeterministic(address app, string calldata version) public view {
        assertEq(token.versionIdFor(app, version), token.versionIdFor(app, version));
    }

    /// Nothing is ever minted against a version id, so it must never collide with a licence id.
    function testFuzz_versionIdsAndLicenceIdsAreDisjoint(string calldata version, uint256 serial)
        public
        view
    {
        assertTrue(
            token.versionIdFor(address(manifest), version)
                != token.licenseIdFor(address(manifest), version, serial)
        );
    }

    // — C-10: mint authorization —

    function test_mintWithValidAuthorization() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);
        assertEq(token.balanceOf(holder, licenseId), 1);
    }

    /// Nothing of the recipient's is consumed by a mint, so a relayer paying gas is legitimate.
    function test_anyoneMaySubmitAMint() public {
        LicenseToken.MintAuthorization memory auth = _auth("1.0.0", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(relayer);
        uint256 licenseId = token.mint(auth, signature);
        assertEq(token.balanceOf(holder, licenseId), 1);
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
            fromLicenseId: 0,
            version: "1.0.0",
            to: holder,
            burnExpected: false,
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
        uint256 a = _mint("1.0.0", holder, 99);
        uint256 b = _mint("1.0.0", holder, 2);
        // Two runnable instances under §2.9 — and now two distinguishable entitlements, so an
        // authorization can name which one it acts on.
        assertEq(token.balanceOf(holder, a), 1);
        assertEq(token.balanceOf(holder, b), 1);
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
    /// A contract developer gets no seeded authorizer, so minting refuses by naming the real
    /// problem — nobody able to sign has been nominated — rather than by reporting a signature
    /// failure against an account that could never have produced one.
    function test_appWithNoNominatedAuthorizerCannotMint() public {
        address contractDeveloper = address(new ContractAccount());
        AppManifest contractOwned = new AppManifest(contractDeveloper);
        vm.prank(contractDeveloper);
        contractOwned.publishVersion(
            "1.0.0", IMAGE_DIGEST, COMPOSE_V1, "ipfs://compose-1", 0, bytes32(0), "ipfs://meta-1"
        );

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(contractOwned),
            fromLicenseId: 0,
            version: "1.0.0",
            to: holder,
            burnExpected: false,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });
        bytes memory signature = _sign(auth, authorizerKey);
        assertEq(contractOwned.mintAuthorizer(), address(0), "no authorizer may be seeded");
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.NoMintAuthorizer.selector, address(contractOwned))
        );
        token.mint(auth, signature);
    }

    // — C-09: uri() resolves through to the manifest —

    function test_uriResolvesThroughToManifestMetadata() public {
        _mint("1.0.0", holder, 1);
        assertEq(token.uri(_lic("1.0.0", 1)), "ipfs://meta-1");
    }

    function test_uriRevertsForATokenNeverMinted() public {
        uint256 tokenId = _lic("2.0.0", 1);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownToken.selector, tokenId));
        token.uri(tokenId);
    }

    function test_originRecordsTheDerivation() public {
        _mint("1.0.0", holder, 1);
        LicenseToken.TokenOrigin memory origin = token.originOf(_lic("1.0.0", 1));
        assertEq(origin.manifest, address(manifest));
        assertEq(origin.version, "1.0.0");
    }

    // — C-07: atomic burn + mint —

    function test_upgradeBurnsOldAndMintsNewInOneTransaction() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, _lic("1.0.0", 1)), 0);
        assertEq(token.balanceOf(holder, _lic("2.0.0", 1)), 1);
    }

    /// ADR 0008: there is no two-instance window, so §2.9 needs no exemption. Asserted by checking
    /// the holder never holds both — which, since it is one transaction, is checked by the totals.
    function test_upgradeLeavesExactlyOneLicence() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        uint256 total =
            token.balanceOf(holder, _lic("1.0.0", 1)) + token.balanceOf(holder, _lic("2.0.0", 1));
        assertEq(total, 1);
    }

    /// The developer's opt-out. Not burning grants an extra runnable instance under §2.9 — the
    /// consequence the developer surface has to state where the knob is set.
    function test_notBurningGrantsAnAdditionalInstance() public {
        vm.prank(developer);
        manifest.setBurnOnUpgrade(false);

        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, _lic("1.0.0", 1)), 1);
        assertEq(token.balanceOf(holder, _lic("2.0.0", 1)), 1);
    }

    /// Doing nothing keeps a holder on the digest they licensed, indefinitely (ADR 0003). A
    /// transition the developer has not priced as permitted does not happen.
    function test_upgradeRequiresAPricedTransition() public {
        _mint("1.0.0", holder, 1);
        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.TransitionNotAllowed.selector, "1.0.0", "2.0.0")
        );
        token.upgrade(auth, signature);
    }

    /// **The property ADR 0023 exists for.** `relayer` is a genuine paying customer of 1.0.0 — they
    /// hold their own licence for it — and names the licence belonging to `holder`. Under the
    /// previous per-version ids this succeeded, because the balance check established only that the
    /// caller was a customer of that version.
    function test_aHolderCannotUpgradeAnotherHoldersLicence() public {
        uint256 theirs = _mint("1.0.0", holder, 1);
        _mint("1.0.0", relayer, 2); // the attacker is a real customer of the same version
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(theirs, "2.0.0", relayer, 3);
        bytes memory signature = _sign(auth, authorizerKey);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.NotAHolder.selector, theirs));
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, theirs), 1, "the victim keeps their licence");
    }

    function test_upgradeRequiresAnExistingLicence() public {
        _allowTransition("1.0.0", "2.0.0");
        uint256 neverMinted = _lic("1.0.0", 99);
        LicenseToken.MintAuthorization memory auth = _auth(neverMinted, "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownLicense.selector, neverMinted));
        token.upgrade(auth, signature);
    }

    /// The authorization is the seller's consent to sell, never the holder's consent to give up
    /// what they hold. A relayer submitting it would supply only half of what a burn needs.
    function test_relayerCannotUpgradeOnAHoldersBehalf() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.RelayedUpgradeNotSupportedInMvp.selector, relayer, holder
            )
        );
        token.upgrade(auth, signature);
    }

    // — downgrades —

    function test_downgradeBlockedByDefault() public {
        _mint("2.0.0", holder, 1);
        _allowTransition("2.0.0", "1.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("2.0.0", 1), "1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.DowngradesNotAllowed.selector, "2.0.0", "1.0.0")
        );
        token.upgrade(auth, signature);
    }

    /// Rollback is the developer's to define (ADR 0004). Note the holder gets the old *version*
    /// with *fresh* state — backward state migration is not realistic, and that belongs in the
    /// developer's documentation rather than in this contract.
    function test_downgradeAllowedWhenDeveloperPermitsIt() public {
        vm.prank(developer);
        manifest.setDowngradesAllowed(true);

        _mint("2.0.0", holder, 1);
        _allowTransition("2.0.0", "1.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("2.0.0", 1), "1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, _lic("1.0.0", 1)), 1);
        assertEq(token.balanceOf(holder, _lic("2.0.0", 1)), 0);
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

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "1.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.SameVersion.selector, "1.0.0"));
        token.upgrade(auth, signature);
    }

    // — the two entry points are not interchangeable —
    //
    // These exist because an earlier revision let `mint` and `upgrade` consume the same signed
    // struct, which made every check in `upgrade` decorative. Each test below is an exploit that
    // worked against that revision.

    /// Burn evasion. The holder pays a discounted upgrade price, then spends the authorization on
    /// `mint` instead — where `burnOnUpgrade` is never consulted — and keeps both versions. Under
    /// spec §2.9 that is two concurrent instances bought for one discounted transition.
    function test_upgradeAuthorizationCannotBeSpentAsAMint() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);

        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.UpgradeAuthorizationIsNotAMint.selector, _lic("1.0.0", 1)
            )
        );
        token.mint(auth, signature);
    }

    /// The same bug without holder complicity. The signed pair is public in the mempool the moment
    /// the holder submits, and `mint` is permissionless, so a bystander front-running it would
    /// defeat the developer's burn setting on a stranger's behalf.
    function test_bystanderCannotFrontRunAnUpgradeIntoAMint() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.UpgradeAuthorizationIsNotAMint.selector, _lic("1.0.0", 1)
            )
        );
        token.mint(auth, signature);

        // And the holder's own upgrade still works, because nothing was consumed.
        vm.prank(holder);
        token.upgrade(auth, signature);
        assertEq(token.balanceOf(holder, _lic("2.0.0", 1)), 1);
    }

    /// Transition-price arbitrage. `upgradePrice` is directional, so a caller free to choose the
    /// source pays the cheap recent-holder discount and burns the worthless version instead — the
    /// signed source is what closes it.
    function test_holderCannotBurnADifferentVersionThanWasPaidFor() public {
        _mint("1.0.0", holder, 1);
        _mint("2.0.0", holder, 2);
        vm.prank(developer);
        manifest.publishVersion(
            "3.0.0", IMAGE_DIGEST, keccak256("c3"), "ipfs://c3", 0, bytes32(0), "ipfs://m3"
        );
        // Cheap for recent holders, expensive from the old version. Both permitted.
        vm.startPrank(developer);
        manifest.setUpgradePrice("2.0.0", "3.0.0", 1 wei, true);
        manifest.setUpgradePrice("1.0.0", "3.0.0", 100 ether, true);
        vm.stopPrank();

        // Authorized for the cheap transition, and it can only spend that one.
        LicenseToken.MintAuthorization memory auth = _auth(_lic("2.0.0", 1), "3.0.0", holder, 3);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, _lic("2.0.0", 1)), 0);
        assertEq(token.balanceOf(holder, _lic("1.0.0", 1)), 1);
        assertEq(token.balanceOf(holder, _lic("3.0.0", 1)), 1);
    }

    function test_mintAuthorizationCannotBeSpentAsAnUpgrade() public {
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth("2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(LicenseToken.MintAuthorizationIsNotAnUpgrade.selector);
        token.upgrade(auth, signature);
    }

    /// The signed payload covers the source, so changing it invalidates the signature rather than
    /// merely being caught by a check that could be reordered away later.
    function test_tamperingWithTheSourceVersionBreaksTheSignature() public {
        vm.prank(developer);
        manifest.publishVersion(
            "3.0.0", IMAGE_DIGEST, keccak256("c3"), "ipfs://c3", 0, bytes32(0), "ipfs://m3"
        );
        _mint("1.0.0", holder, 1);
        _mint("2.0.0", holder, 2);
        _allowTransition("1.0.0", "3.0.0");
        _allowTransition("2.0.0", "3.0.0");

        // Signed for the 1.0.0 source; swapped to a source that would otherwise pass every check
        // before the signature — it exists, it is held, it is priced, and it is not a downgrade.
        LicenseToken.MintAuthorization memory signed = _auth(_lic("1.0.0", 1), "3.0.0", holder, 3);
        bytes memory signature = _sign(signed, authorizerKey);

        LicenseToken.MintAuthorization memory tampered = signed;
        tampered.fromLicenseId = _lic("2.0.0", 1);

        vm.prank(holder);
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        token.upgrade(tampered, signature);
    }

    // — instance binding: holding a licence is not owning an instance —

    bytes32 internal constant INSTANCE_A = bytes32(uint256(0xA1));
    bytes32 internal constant INSTANCE_B = bytes32(uint256(0xB2));

    function test_aHolderBindsTheirOwnInstance() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);

        vm.prank(holder);
        token.bindInstance(licenseId, INSTANCE_A);

        assertEq(token.instanceOf(licenseId), INSTANCE_A);
        assertEq(token.claimedBy(INSTANCE_A), licenseId);
    }

    /// **The property this binding exists for.** `relayer` is a genuine customer holding a genuine
    /// licence for the same version, and still cannot point it at somebody else's instance.
    function test_aHolderCannotClaimAnotherHoldersInstance() public {
        uint256 alice = _mint("1.0.0", holder, 1);
        uint256 mallory = _mint("1.0.0", relayer, 2);

        vm.prank(holder);
        token.bindInstance(alice, INSTANCE_A);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.InstanceAlreadyClaimed.selector, INSTANCE_A, alice)
        );
        token.bindInstance(mallory, INSTANCE_A);

        assertEq(token.instanceOf(alice), INSTANCE_A, "the victim keeps their instance");
    }

    /// A claim is permanent, so waiting for a holder to move on does not free their instance.
    function test_anInstanceStaysClaimedAfterTheHolderRebinds() public {
        uint256 alice = _mint("1.0.0", holder, 1);
        uint256 mallory = _mint("1.0.0", relayer, 2);

        vm.startPrank(holder);
        token.bindInstance(alice, INSTANCE_A);
        token.bindInstance(alice, INSTANCE_B); // the first instance was destroyed
        vm.stopPrank();

        assertEq(token.instanceOf(alice), INSTANCE_B);
        assertEq(token.claimedBy(INSTANCE_A), alice, "the abandoned instance is still claimed");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.InstanceAlreadyClaimed.selector, INSTANCE_A, alice)
        );
        token.bindInstance(mallory, INSTANCE_A);
    }

    /// Instances are destroyed; a holder needs a path to a replacement.
    function test_aHolderCanRebindToAFreshInstance() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);

        vm.startPrank(holder);
        token.bindInstance(licenseId, INSTANCE_A);
        token.bindInstance(licenseId, INSTANCE_B);
        vm.stopPrank();

        assertEq(token.instanceOf(licenseId), INSTANCE_B);
    }

    function test_onlyTheHolderMayBind() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.NotLicenseHolder.selector, relayer, licenseId)
        );
        token.bindInstance(licenseId, INSTANCE_A);
    }

    /// Zero means "unbound", so binding to it would make an unbound licence look bound.
    function test_anEmptyInstanceIdIsRefused() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);
        vm.prank(holder);
        vm.expectRevert(LicenseToken.EmptyInstanceId.selector);
        token.bindInstance(licenseId, bytes32(0));
    }

    /// **Without this the act of upgrading would lock a holder out of their own instance:** the new
    /// licence would be unbound, and rebinding would be refused because the old licence's claim is
    /// permanent.
    function test_anUpgradeCarriesTheBindingToTheNewLicence() public {
        uint256 oldLicense = _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        vm.prank(holder);
        token.bindInstance(oldLicense, INSTANCE_A);

        LicenseToken.MintAuthorization memory auth = _auth(oldLicense, "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        uint256 newLicense = token.upgrade(auth, signature);

        assertEq(token.instanceOf(newLicense), INSTANCE_A, "the instance follows the holder");
        assertEq(token.claimedBy(INSTANCE_A), newLicense);
        assertEq(token.instanceOf(oldLicense), bytes32(0), "the spent licence keeps nothing");
    }

    /// §2.6: transfer the token, transfer the living instance. The binding is keyed on the licence,
    /// so it moves with it and needs no separate handover act.
    function test_transferCarriesTheInstanceToTheNewHolder() public {
        uint256 licenseId = _mint("1.0.0", holder, 1);
        vm.prank(holder);
        token.bindInstance(licenseId, INSTANCE_A);

        vm.prank(holder);
        token.safeTransferFrom(holder, relayer, licenseId, 1, "");

        assertEq(token.instanceOf(licenseId), INSTANCE_A, "the binding follows the licence");
        assertEq(token.balanceOf(relayer, licenseId), 1);
        // And the previous holder can no longer bind it anywhere, because they hold nothing.
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.NotLicenseHolder.selector, holder, licenseId)
        );
        token.bindInstance(licenseId, INSTANCE_B);
    }

    // — L-2: a delegation that could never work fails where the mistake was made —

    function test_cannotDelegateMintingToAContractAccount() public {
        address contractAuthorizer = address(new ContractAccount());
        vm.prank(developer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppManifest.SmartAccountNotSupportedInMvp.selector, contractAuthorizer
            )
        );
        manifest.setMintAuthorizer(contractAuthorizer);
    }

    function test_upgradeRejectsNonceReplay() public {
        // Burning off, so the source licence survives the first upgrade and the replay reaches the
        // nonce check rather than stopping at `NotAHolder`.
        vm.prank(developer);
        manifest.setBurnOnUpgrade(false);

        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        token.upgrade(auth, signature);

        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(
                LicenseToken.NonceAlreadyUsed.selector, address(manifest), uint256(2)
            )
        );
        token.upgrade(auth, signature);
    }

    // — T-08: the refusals nothing had exercised —

    /// Zero is what `_origin` holds for every id that was never issued, and ids are computed
    /// offline from an address and a string (`licenseIdFor`), so *any* number is a well-formed
    /// query. Returning the zeroed struct would tell a caller that licence 12345 exists, belongs to
    /// app `address(0)`, and names version "" — three false statements, none of them detectable.
    function test_originOfRefusesATokenThatWasNeverIssued() public {
        uint256 neverIssued = _lic("1.0.0", 1);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownToken.selector, neverIssued));
        token.originOf(neverIssued);

        // And after a real mint, the *next* serial is still unknown — the guard tracks issuance,
        // not merely whether the app exists.
        _mint("1.0.0", holder, 1);
        token.originOf(_lic("1.0.0", 1));
        uint256 nextSerial = _lic("1.0.0", 2);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownToken.selector, nextSerial));
        token.originOf(nextSerial);
    }

    /// **A licence is an entitlement to one app, and the id alone does not say which.** The
    /// authorization names a manifest and the licence records one; if `upgrade` did not compare
    /// them, a holder could present a licence for app A while naming app B — burning something of
    /// no value to B and minting a real entitlement to it. The signature does not prevent this:
    /// B's own authorizer signed it, having been told only an id.
    function test_upgradeRefusesALicenceBelongingToADifferentApp() public {
        uint256 licence = _mint("1.0.0", holder, 1);

        AppManifest otherApp = new AppManifest(developer);
        vm.startPrank(developer);
        otherApp.publishVersion(
            "1.0.0", IMAGE_DIGEST, COMPOSE_V1, "ipfs://other-1", 0, bytes32(0), ""
        );
        otherApp.publishVersion(
            "2.0.0", IMAGE_DIGEST, COMPOSE_V2, "ipfs://other-2", 0, bytes32(0), ""
        );
        otherApp.setMintAuthorizer(authorizer);
        otherApp.setUpgradePrice("1.0.0", "2.0.0", 1 ether, true);
        vm.stopPrank();

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(otherApp),
            fromLicenseId: licence, // issued by `manifest`, not by `otherApp`
            version: "2.0.0",
            to: holder,
            burnExpected: otherApp.burnOnUpgrade(),
            nonce: 2,
            expiry: block.timestamp + 1 hours
        });

        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownLicense.selector, licence));
        token.upgrade(auth, signature);
    }

    /// The same guard, on the simpler input: an id no app ever issued.
    function test_upgradeRefusesALicenceThatWasNeverIssued() public {
        _allowTransition("1.0.0", "2.0.0");
        uint256 phantom = _lic("1.0.0", 99);

        LicenseToken.MintAuthorization memory auth = _auth(phantom, "2.0.0", holder, 1);
        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.UnknownLicense.selector, phantom));
        token.upgrade(auth, signature);
    }

    /// Reached only through a manifest built to lie, which is the point: `auth.manifest` is
    /// caller-supplied, so this guard's job is to hold when the contract on the other end is
    /// hostile. It refuses rather than reading index 0 as "position zero" and computing a
    /// downgrade against it.
    function test_upgradeRefusesAVersionItsOwnManifestDisowns() public {
        LyingManifest lying = new LyingManifest(authorizer);

        LicenseToken.MintAuthorization memory mintAuth = LicenseToken.MintAuthorization({
            manifest: address(lying),
            fromLicenseId: 0,
            version: "1.0.0",
            to: holder,
            burnExpected: false,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });
        uint256 licence = token.mint(mintAuth, _sign(mintAuth, authorizerKey));

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(lying),
            fromLicenseId: licence,
            version: "2.0.0",
            to: holder,
            burnExpected: false,
            nonce: 2,
            expiry: block.timestamp + 1 hours
        });

        bytes memory signature = _sign(auth, authorizerKey);
        vm.prank(holder);
        vm.expectRevert(
            abi.encodeWithSelector(LicenseToken.TransitionNotAllowed.selector, "1.0.0", "2.0.0")
        );
        token.upgrade(auth, signature);
    }

    /// **The one term whose reversal destroys something.** Burn-on-upgrade is the developer's to
    /// set and theirs to change, but changing it between the moment a holder is quoted and the
    /// moment they execute changes what the transaction *does*: not burning yields an extra
    /// runnable instance under §2.9, burning takes the old entitlement away for good. So the
    /// authorization carries the term it was sold under and the contract refuses if the manifest no
    /// longer agrees. Every other term flipping merely reverts; this one would succeed, quietly,
    /// having burned a licence the holder was told they would keep.
    function test_upgradeRefusesWhenTheBurnTermChangedAfterTheSale() public {
        assertTrue(manifest.burnOnUpgrade(), "the default this test depends on");
        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        // Signed while burning is in force — `_auth` reads the manifest, as an honest payment
        // service would at the moment it charged.
        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        assertTrue(auth.burnExpected);

        vm.prank(developer);
        manifest.setBurnOnUpgrade(false);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.BurnTermChanged.selector, true, false));
        token.upgrade(auth, signature);
    }

    /// And the other direction, which is the one that costs the holder something: quoted without a
    /// burn, executed with one.
    function test_upgradeRefusesWhenBurningWasTurnedOnAfterTheSale() public {
        vm.prank(developer);
        manifest.setBurnOnUpgrade(false);

        _mint("1.0.0", holder, 1);
        _allowTransition("1.0.0", "2.0.0");

        LicenseToken.MintAuthorization memory auth = _auth(_lic("1.0.0", 1), "2.0.0", holder, 2);
        bytes memory signature = _sign(auth, authorizerKey);
        assertFalse(auth.burnExpected);

        vm.prank(developer);
        manifest.setBurnOnUpgrade(true);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(LicenseToken.BurnTermChanged.selector, false, true));
        token.upgrade(auth, signature);

        assertEq(token.balanceOf(holder, _lic("1.0.0", 1)), 1, "the licence must still be there");
    }
}
