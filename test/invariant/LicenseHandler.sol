// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../../src/AppManifest.sol";
import {LicenseToken} from "../../src/LicenseToken.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

/// @title LicenseHandler
/// @notice Drives random-but-valid sequences of publishing, minting and upgrading, and keeps the
/// shadow accounting the invariants are checked against.
///
/// @dev Written to *succeed* rather than to bounce off input validation. An unguided fuzzer spends
/// almost all of its calls reverting on a bad version string or an unpriced transition, and a run
/// where nothing succeeded proves nothing while reporting a pass — the failure mode where a test
/// suite is green because it never ran anything.
contract LicenseHandler is CommonBase, StdCheats, StdUtils {
    LicenseToken public immutable token;
    AppManifest[] public manifests;
    address[] public actors;

    uint256 internal constant AUTHORIZER_KEY = 0xA11CE;
    address internal immutable authorizer;
    address internal immutable developer;

    uint256 internal nonceCounter;

    // — shadow accounting —

    /// @notice Every version string ever published, per manifest index.
    mapping(uint256 manifestIndex => string[] versions) public published;
    /// @notice What the record said when it was first published (I5: it must never change).
    mapping(bytes32 versionKey => bytes32 composeHash) public publishedComposeHash;
    mapping(bytes32 versionKey => bytes32 imageDigest) public publishedImageDigest;
    mapping(bytes32 versionKey => string composeURI) public publishedComposeURI;

    mapping(uint256 tokenId => uint256 count) public ghostMinted;
    mapping(uint256 tokenId => uint256 count) public ghostBurned;

    /// @notice Set if an upgrade ever left a holder with a different total than it should have.
    /// @dev A flag rather than an assertion inside the action, so a violation is reported by the
    /// invariant with the full failing sequence attached rather than as a bare revert.
    bool public atomicityViolated;
    /// @notice Set if an upgrade under `burnOnUpgrade` was ever observed mid-flight with both.
    bool public bothHeldSimultaneously;

    uint256 public mintCount;
    uint256 public upgradeCount;
    uint256 public publishCount;

    constructor(LicenseToken token_, address developer_, uint256 manifestCount_) {
        token = token_;
        developer = developer_;
        authorizer = vm.addr(AUTHORIZER_KEY);

        for (uint256 i = 0; i < manifestCount_; i++) {
            AppManifest m = new AppManifest(developer_);
            vm.prank(developer_);
            m.setMintAuthorizer(authorizer);
            manifests.push(m);
            // Two versions each, so an upgrade is reachable from the first call rather than only
            // after the fuzzer happens to publish twice on the same app. A shallow run that never
            // reaches the interesting operation is a run that proves nothing.
            _publish(i, 0);
            _publish(i, 0);
        }

        actors.push(address(0xA1));
        actors.push(address(0xA2));
        actors.push(address(0xA3));
    }

    function manifestCount() external view returns (uint256) {
        return manifests.length;
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function publishedCount(uint256 manifestIndex) external view returns (uint256) {
        return published[manifestIndex].length;
    }

    function publishedAt(uint256 manifestIndex, uint256 i) external view returns (string memory) {
        return published[manifestIndex][i];
    }

    // — actions —

    function publishVersion(uint256 manifestSeed, uint256 capabilities) external {
        _publish(_boundManifest(manifestSeed), capabilities);
    }

    function _publish(uint256 mi, uint256 capabilities) internal {
        AppManifest m = manifests[mi];

        string memory version = string.concat("v", vm.toString(published[mi].length));
        bytes32 composeHash = keccak256(abi.encode(mi, version, "compose"));
        bytes32 imageDigest = keccak256(abi.encode(mi, version, "image"));
        string memory composeURI = string.concat("ipfs://", vm.toString(composeHash));

        vm.prank(developer);
        m.publishVersion(
            version,
            imageDigest,
            composeHash,
            composeURI,
            capabilities,
            bytes32(0),
            string.concat("ipfs://meta-", version)
        );

        published[mi].push(version);
        bytes32 key = _versionKey(mi, version);
        publishedComposeHash[key] = composeHash;
        publishedImageDigest[key] = imageDigest;
        publishedComposeURI[key] = composeURI;
        publishCount++;
    }

    function mint(uint256 manifestSeed, uint256 versionSeed, uint256 actorSeed) external {
        uint256 mi = _boundManifest(manifestSeed);
        if (published[mi].length == 0) return;

        string memory version = published[mi][_bound(versionSeed, published[mi].length)];
        address to = actors[_bound(actorSeed, actors.length)];

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(manifests[mi]),
            fromVersion: "",
            version: version,
            to: to,
            nonce: ++nonceCounter,
            expiry: block.timestamp + 1 days
        });

        token.mint(auth, _sign(auth));
        ghostMinted[token.tokenIdFor(address(manifests[mi]), version)]++;
        mintCount++;
    }

    /// @dev Prices the transition first when it is not already priced, so upgrades actually happen
    /// rather than the fuzzer discovering only the revert.
    function upgrade(uint256 manifestSeed, uint256 fromSeed, uint256 toSeed, uint256 actorSeed)
        external
    {
        uint256 mi = _boundManifest(manifestSeed);
        uint256 count = published[mi].length;
        if (count < 2) return;

        AppManifest m = manifests[mi];

        // Steer into a usable transition rather than abandoning the call. Every `return` here is a
        // sequence in which the operation under test never ran, and at shallow depth those add up
        // fast enough to make the whole suite vacuous — which is worse than a slow suite, because
        // it reports green.
        uint256 fromIndex = _bound(fromSeed, count);
        uint256 toIndex = _bound(toSeed, count);
        if (fromIndex == toIndex) toIndex = (toIndex + 1) % count;
        // Publication order is the ordering, so a lower index is a downgrade. Swapping keeps the
        // pair rather than discarding it; the developer's downgrade knob is exercised by the
        // sequences where `setDowngradesAllowed(true)` came first.
        if (toIndex < fromIndex && !m.downgradesAllowed()) {
            (fromIndex, toIndex) = (toIndex, fromIndex);
        }

        string memory from = published[mi][fromIndex];
        string memory to = published[mi][toIndex];

        address actor = actors[_bound(actorSeed, actors.length)];
        uint256 fromTokenId = token.tokenIdFor(address(m), from);
        // Give the actor something to upgrade from rather than abandoning the call. Without this
        // the fuzzer has to mint and upgrade the same (app, version, actor) triple by coincidence,
        // which a shallow sequence almost never does.
        if (token.balanceOf(actor, fromTokenId) == 0) {
            _mintTo(mi, from, actor);
        }

        (, bool allowed) = m.upgradePrice(from, to);
        if (!allowed) {
            vm.prank(developer);
            m.setUpgradePrice(from, to, 0, true);
        }

        uint256 toTokenId = token.tokenIdFor(address(m), to);
        bool burns = m.burnOnUpgrade();
        uint256 totalBefore =
            token.balanceOf(actor, fromTokenId) + token.balanceOf(actor, toTokenId);

        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(m),
            fromVersion: from,
            version: to,
            to: actor,
            nonce: ++nonceCounter,
            expiry: block.timestamp + 1 days
        });

        // Signed before the prank: `_sign` makes an external call to `hashMintAuthorization`, and
        // it would otherwise be the call the prank applies to — leaving the handler as msg.sender
        // and every upgrade rejected as a relayed one.
        bytes memory signature = _sign(auth);
        vm.prank(actor);
        token.upgrade(auth, signature);

        ghostMinted[toTokenId]++;
        if (burns) ghostBurned[fromTokenId]++;
        upgradeCount++;

        uint256 totalAfter = token.balanceOf(actor, fromTokenId) + token.balanceOf(actor, toTokenId);
        uint256 expected = burns ? totalBefore : totalBefore + 1;
        if (totalAfter != expected) atomicityViolated = true;
        // Under burn, the holder's count across the pair is unchanged — there was never a moment
        // with two, which is why §2.9 needs no upgrade exemption (ADR 0008).
        if (burns && totalAfter > totalBefore) bothHeldSimultaneously = true;
    }

    function setBurnOnUpgrade(uint256 manifestSeed, bool burn) external {
        vm.prank(developer);
        manifests[_boundManifest(manifestSeed)].setBurnOnUpgrade(burn);
    }

    function setDowngradesAllowed(uint256 manifestSeed, bool allowed) external {
        vm.prank(developer);
        manifests[_boundManifest(manifestSeed)].setDowngradesAllowed(allowed);
    }

    function transfer(uint256 manifestSeed, uint256 versionSeed, uint256 fromSeed, uint256 toSeed)
        external
    {
        uint256 mi = _boundManifest(manifestSeed);
        if (published[mi].length == 0) return;

        string memory version = published[mi][_bound(versionSeed, published[mi].length)];
        uint256 tokenId = token.tokenIdFor(address(manifests[mi]), version);
        address from = actors[_bound(fromSeed, actors.length)];
        address to = actors[_bound(toSeed, actors.length)];
        if (from == to || token.balanceOf(from, tokenId) == 0) return;

        vm.prank(from);
        token.safeTransferFrom(from, to, tokenId, 1, "");
    }

    // — internals —

    function _mintTo(uint256 mi, string memory version, address to) internal {
        LicenseToken.MintAuthorization memory auth = LicenseToken.MintAuthorization({
            manifest: address(manifests[mi]),
            fromVersion: "",
            version: version,
            to: to,
            nonce: ++nonceCounter,
            expiry: block.timestamp + 1 days
        });
        token.mint(auth, _sign(auth));
        ghostMinted[token.tokenIdFor(address(manifests[mi]), version)]++;
        mintCount++;
    }

    function _sign(LicenseToken.MintAuthorization memory auth)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORIZER_KEY, token.hashMintAuthorization(auth));
        return abi.encodePacked(r, s, v);
    }

    function _bound(uint256 seed, uint256 length) internal pure returns (uint256) {
        return length == 0 ? 0 : seed % length;
    }

    function _boundManifest(uint256 seed) internal view returns (uint256) {
        return seed % manifests.length;
    }

    function _versionKey(uint256 manifestIndex, string memory version)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(manifestIndex, version));
    }

    function versionKey(uint256 manifestIndex, string memory version)
        external
        pure
        returns (bytes32)
    {
        return _versionKey(manifestIndex, version);
    }
}
