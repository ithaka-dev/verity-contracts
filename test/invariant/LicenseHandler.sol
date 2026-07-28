// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../../src/AppManifest.sol";
import {LicenseToken} from "../../src/LicenseToken.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

/// @title LicenseHandler
/// @notice Drives sequences of publishing, minting and upgrading, keeps the shadow accounting the
/// invariants are checked against, and — the part that took a second review to get right —
/// **attempts the things that must not work.**
///
/// @dev ### Why the attempted violations are here
///
/// An earlier version of this handler was written so that every call succeeded: it synthesised
/// fresh version strings, incremented nonces, swapped indices to dodge a forbidden downgrade, and
/// always signed correctly with the one key it had. It reported zero reverts across every run,
/// which read like thoroughness and was the opposite.
///
/// A mutation test settled it. Twelve real bugs were reintroduced one at a time; the suite caught
/// two. Deleting `requireValidSignature` from `LicenseToken` entirely left it green, as did
/// reintroducing both of the high-severity authorization bugs this suite exists to guard against.
///
/// The cause is structural rather than careless. Conservation properties — supply equals mints
/// minus burns, records never change — are the natural thing to assert about a token, and they are
/// blind to authorization: a licence minted by an attacker is conserved exactly as carefully as one
/// minted legitimately. **Every bug this contract has actually shipped was an authorization bug**,
/// so a suite built only from conservation properties could not have found any of them.
///
/// So `tryGuards` attempts each forbidden operation against whatever state the fuzzer has reached
/// and sets `guardBypassed` if one succeeds. That is the difference from a unit test: the same
/// attempts run against thousands of states nobody enumerated, rather than against one fixture.
contract LicenseHandler is CommonBase, StdCheats, StdUtils {
    LicenseToken public immutable token;
    AppManifest[] public manifests;
    address[] public actors;

    uint256 internal constant AUTHORIZER_KEY = 0xA11CE;
    /// A key that is not the authorizer's, for signatures that must not verify.
    uint256 internal constant STRANGER_KEY = 0xBADBAD;
    address internal immutable authorizer;
    address internal immutable developer;
    address internal constant STRANGER = address(0xBEEF);

    uint256 internal nonceCounter;

    // — shadow accounting —

    mapping(uint256 manifestIndex => string[] versions) public published;
    mapping(bytes32 versionKey => bytes32 composeHash) public publishedComposeHash;
    mapping(bytes32 versionKey => bytes32 imageDigest) public publishedImageDigest;
    mapping(bytes32 versionKey => string composeURI) public publishedComposeURI;

    mapping(uint256 tokenId => uint256 count) public ghostMinted;
    mapping(uint256 tokenId => uint256 count) public ghostBurned;

    /// @notice Set if an upgrade ever left a holder with a different total than it should have.
    bool public atomicityViolated;

    /// @notice Set if any operation that must be refused was accepted.
    bool public guardBypassed;
    /// @notice Which one, so a failure names the bug rather than only reporting that there is one.
    string public bypassDetail;

    uint256 public mintCount;
    uint256 public upgradeCount;
    uint256 public publishCount;
    /// @notice How many times the forbidden operations were attempted. Zero means this suite proved
    /// nothing about authorization, however green it looks.
    uint256 public guardAttempts;

    constructor(LicenseToken token_, address developer_, uint256 manifestCount_) {
        token = token_;
        developer = developer_;
        authorizer = vm.addr(AUTHORIZER_KEY);

        for (uint256 i = 0; i < manifestCount_; i++) {
            AppManifest m = new AppManifest(developer_);
            vm.prank(developer_);
            m.setMintAuthorizer(authorizer);
            manifests.push(m);
            _publish(i, 0);
            _publish(i, 0);
        }

        actors.push(address(0xA1));
        actors.push(address(0xA2));
        actors.push(address(0xA3));
        // The handler holds licences too, so it can attempt a relayed upgrade against its own
        // balance. Included in `actors` so supply accounting still covers every holder.
        actors.push(address(this));
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

    // ---------------------------------------------------------------------------------------
    // Actions that should succeed
    // ---------------------------------------------------------------------------------------

    function publishVersion(uint256 manifestSeed, uint256 capabilities) external {
        _publish(_boundManifest(manifestSeed), capabilities);
    }

    function mint(uint256 manifestSeed, uint256 versionSeed, uint256 actorSeed) external {
        uint256 mi = _boundManifest(manifestSeed);
        if (published[mi].length == 0) return;
        _mintTo(mi, published[mi][_bound(versionSeed, published[mi].length)], _actor(actorSeed));
    }

    function upgrade(uint256 manifestSeed, uint256 fromSeed, uint256 toSeed, uint256 actorSeed)
        external
    {
        uint256 mi = _boundManifest(manifestSeed);
        uint256 count = published[mi].length;
        if (count < 2) return;

        AppManifest m = manifests[mi];

        uint256 fromIndex = _bound(fromSeed, count);
        uint256 toIndex = _bound(toSeed, count);
        if (fromIndex == toIndex) toIndex = (toIndex + 1) % count;
        if (toIndex < fromIndex && !m.downgradesAllowed()) {
            (fromIndex, toIndex) = (toIndex, fromIndex);
        }

        string memory from = published[mi][fromIndex];
        string memory to = published[mi][toIndex];

        address actor = _actor(actorSeed);
        uint256 fromTokenId = token.tokenIdFor(address(m), from);
        if (token.balanceOf(actor, fromTokenId) == 0) _mintTo(mi, from, actor);

        (, bool allowed) = m.upgradePrice(from, to);
        if (!allowed) {
            vm.prank(developer);
            m.setUpgradePrice(from, to, 0, true);
        }

        uint256 toTokenId = token.tokenIdFor(address(m), to);
        bool burns = m.burnOnUpgrade();
        uint256 totalBefore =
            token.balanceOf(actor, fromTokenId) + token.balanceOf(actor, toTokenId);

        LicenseToken.MintAuthorization memory auth =
            _auth(mi, from, to, actor, burns, ++nonceCounter, block.timestamp + 1 days);

        bytes memory signature = _sign(auth);
        vm.prank(actor);
        token.upgrade(auth, signature);

        ghostMinted[toTokenId]++;
        if (burns) ghostBurned[fromTokenId]++;
        upgradeCount++;

        uint256 totalAfter = token.balanceOf(actor, fromTokenId) + token.balanceOf(actor, toTokenId);
        if (totalAfter != (burns ? totalBefore : totalBefore + 1)) atomicityViolated = true;
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
        address from = _actor(fromSeed);
        address to = _actor(toSeed);
        if (from == to || token.balanceOf(from, tokenId) == 0) return;

        vm.prank(from);
        token.safeTransferFrom(from, to, tokenId, 1, "");
    }

    /// @dev Without time moving, an expiry in the past is unreachable and the expiry check is
    /// untestable by this suite.
    function advanceTime(uint256 seconds_) external {
        vm.warp(block.timestamp + _bound(seconds_, 7 days) + 1);
    }

    // ---------------------------------------------------------------------------------------
    // Attempted violations — every one of these must fail
    // ---------------------------------------------------------------------------------------

    /// @notice Attempt each forbidden operation against the current state.
    /// @dev All of them in one action rather than one action each, so coverage does not depend on
    /// the fuzzer happening to select nine rare selectors within a single sequence. The value over
    /// a unit test is that these run against states nobody enumerated.
    function tryGuards(uint256 manifestSeed, uint256 actorSeed) external {
        uint256 mi = _boundManifest(manifestSeed);
        if (published[mi].length < 2) return;

        AppManifest m = manifests[mi];
        address actor = _actor(actorSeed);
        string memory from = published[mi][0];
        string memory to = published[mi][1];

        if (token.balanceOf(actor, token.tokenIdFor(address(m), from)) == 0) {
            _mintTo(mi, from, actor);
        }
        (, bool allowed) = m.upgradePrice(from, to);
        if (!allowed) {
            vm.prank(developer);
            m.setUpgradePrice(from, to, 0, true);
        }
        bool burns = m.burnOnUpgrade();

        _guardUpgradeAuthIsNotAMint(mi, from, to, actor, burns);
        _guardMintAuthIsNotAnUpgrade(mi, to, actor, burns);
        _guardWrongKeyIsRefused(mi, to, actor, burns);
        _guardExpiredIsRefused(mi, to, actor, burns);
        _guardRelayedUpgradeIsRefused(mi, from, to, actor, burns);
        _guardNonceCannotBeReplayed(mi, to, actor, burns);
        _guardUnpublishedVersionCannotMint(mi, actor, burns);
        _guardBurnTermCannotBeFlipped(mi, from, to, actor, burns);
        _guardForbiddenDowngradeIsRefused(mi, from, to, actor, burns);
        _guardVersionCannotBeRepublished(mi);
        _guardStrangerCannotPublish(mi);

        guardAttempts++;
    }

    /// The critical bug from the first review: an upgrade authorization spent as a plain mint,
    /// where none of the developer's knobs are consulted.
    function _guardUpgradeAuthIsNotAMint(
        uint256 mi,
        string memory from,
        string memory to,
        address actor,
        bool burns
    ) private {
        LicenseToken.MintAuthorization memory auth = _auth(
            mi, from, to, actor, burns, ++nonceCounter, block.timestamp + 1 days
        );
        bytes memory signature = _sign(auth);
        try token.mint(auth, signature) {
            _bypassed("upgrade authorization was accepted by mint");
        } catch {}
    }

    function _guardMintAuthIsNotAnUpgrade(uint256 mi, string memory to, address actor, bool burns)
        private
    {
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, "", to, actor, burns, ++nonceCounter, block.timestamp + 1 days);
        bytes memory signature = _sign(auth);
        vm.prank(actor);
        try token.upgrade(auth, signature) {
            _bypassed("mint authorization was accepted by upgrade");
        } catch {}
    }

    /// If this ever passes, signature verification is not running at all.
    function _guardWrongKeyIsRefused(uint256 mi, string memory to, address actor, bool burns)
        private
    {
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, "", to, actor, burns, ++nonceCounter, block.timestamp + 1 days);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(STRANGER_KEY, token.hashMintAuthorization(auth));
        try token.mint(auth, abi.encodePacked(r, s, v)) {
            _bypassed("a signature from the wrong key was accepted");
        } catch {}
    }

    function _guardExpiredIsRefused(uint256 mi, string memory to, address actor, bool burns)
        private
    {
        // Guards the subtraction below, not a security decision — this is test scaffolding.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp == 0) return;
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, "", to, actor, burns, ++nonceCounter, block.timestamp - 1);
        bytes memory signature = _sign(auth);
        try token.mint(auth, signature) {
            _bypassed("an expired authorization was accepted");
        } catch {}
    }

    /// Burning is destructive, so the holder must submit. A relayer supplies only the seller's
    /// consent, never the holder's.
    ///
    /// @dev The handler must itself hold the source licence for this to test anything. Without
    /// that, removing the guard still reverts — on `NotAHolder` — and the mutant survives while
    /// looking caught. `upgrade` mints to `msg.sender`, so the real hazard is a third party
    /// consuming an authorization issued to someone else and taking the new licence themselves.
    function _guardRelayedUpgradeIsRefused(
        uint256 mi,
        string memory from,
        string memory to,
        address actor,
        bool burns
    ) private {
        address beneficiary = actor == address(this) ? actors[0] : actor;
        if (token.balanceOf(address(this), token.tokenIdFor(address(manifests[mi]), from)) == 0) {
            _mintTo(mi, from, address(this));
        }
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, from, to, beneficiary, burns, ++nonceCounter, block.timestamp + 1 days);
        bytes memory signature = _sign(auth);
        // No prank: the handler is msg.sender, which is not `auth.to`.
        try token.upgrade(auth, signature) {
            _bypassed("a relayed upgrade was accepted");
        } catch {}
    }

    function _guardNonceCannotBeReplayed(uint256 mi, string memory to, address actor, bool burns)
        private
    {
        uint256 nonce = ++nonceCounter;
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, "", to, actor, burns, nonce, block.timestamp + 1 days);
        bytes memory signature = _sign(auth);

        try token.mint(auth, signature) {
            ghostMinted[token.tokenIdFor(address(manifests[mi]), to)]++;
            mintCount++;
        } catch {
            return; // the first mint failed for an unrelated reason; nothing to replay
        }
        try token.mint(auth, signature) {
            _bypassed("a nonce was spent twice");
        } catch {}
    }

    function _guardUnpublishedVersionCannotMint(uint256 mi, address actor, bool burns) private {
        LicenseToken.MintAuthorization memory auth = _auth(
            mi,
            "",
            "never-published-version",
            actor,
            burns,
            ++nonceCounter,
            block.timestamp + 1 days
        );
        bytes memory signature = _sign(auth);
        try token.mint(auth, signature) {
            _bypassed("a licence was minted for a version that was never published");
        } catch {}
    }

    /// The economic term the holder paid for must not be changeable under an in-flight upgrade.
    function _guardBurnTermCannotBeFlipped(
        uint256 mi,
        string memory from,
        string memory to,
        address actor,
        bool burns
    ) private {
        LicenseToken.MintAuthorization memory auth = _auth(
            mi, from, to, actor, !burns, ++nonceCounter, block.timestamp + 1 days
        );
        bytes memory signature = _sign(auth);
        vm.prank(actor);
        try token.upgrade(auth, signature) {
            _bypassed("an upgrade ran under different burn terms than were signed");
        } catch {}
    }

    /// Rollback is the developer's to permit. While they have not, a transition to an earlier
    /// publication index must be refused even when it is priced and the holder is genuine.
    function _guardForbiddenDowngradeIsRefused(
        uint256 mi,
        string memory earlier,
        string memory later,
        address actor,
        bool burns
    ) private {
        AppManifest m = manifests[mi];
        if (m.downgradesAllowed()) return; // permitted right now; nothing forbidden to attempt

        if (token.balanceOf(actor, token.tokenIdFor(address(m), later)) == 0) {
            _mintTo(mi, later, actor);
        }
        (, bool allowed) = m.upgradePrice(later, earlier);
        if (!allowed) {
            vm.prank(developer);
            m.setUpgradePrice(later, earlier, 0, true);
        }

        LicenseToken.MintAuthorization memory auth =
            _auth(mi, later, earlier, actor, burns, ++nonceCounter, block.timestamp + 1 days);
        bytes memory signature = _sign(auth);
        vm.prank(actor);
        try token.upgrade(auth, signature) {
            _bypassed("a downgrade ran while the developer forbade downgrades");
        } catch {}
    }

    /// I5: a published record is immutable.
    function _guardVersionCannotBeRepublished(uint256 mi) private {
        AppManifest m = manifests[mi];
        string memory existing = published[mi][0];
        vm.prank(developer);
        try m.publishVersion(
            existing, keccak256("x"), keccak256("y"), "ipfs://z", 0, bytes32(0), "ipfs://w"
        ) {
            _bypassed("a published version was overwritten");
        } catch {}
    }

    function _guardStrangerCannotPublish(uint256 mi) private {
        AppManifest m = manifests[mi];
        vm.prank(STRANGER);
        try m.publishVersion(
            "stranger-version",
            keccak256("x"),
            keccak256("y"),
            "ipfs://z",
            0,
            bytes32(0),
            "ipfs://w"
        ) {
            _bypassed("a non-developer published a version");
        } catch {}
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    /// @dev `_mint` calls this on any contract recipient; without it the handler cannot hold a
    /// licence and the relay guard above has nothing to work with.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function _bypassed(string memory detail) private {
        guardBypassed = true;
        bypassDetail = detail;
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

    function _mintTo(uint256 mi, string memory version, address to) internal {
        LicenseToken.MintAuthorization memory auth =
            _auth(mi, "", version, to, false, ++nonceCounter, block.timestamp + 1 days);
        token.mint(auth, _sign(auth));
        ghostMinted[token.tokenIdFor(address(manifests[mi]), version)]++;
        mintCount++;
    }

    function _auth(
        uint256 mi,
        string memory fromVersion,
        string memory version,
        address to,
        bool burnExpected,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (LicenseToken.MintAuthorization memory) {
        return LicenseToken.MintAuthorization({
            manifest: address(manifests[mi]),
            fromVersion: fromVersion,
            version: version,
            to: to,
            burnExpected: burnExpected,
            nonce: nonce,
            expiry: expiry
        });
    }

    function _sign(LicenseToken.MintAuthorization memory auth)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORIZER_KEY, token.hashMintAuthorization(auth));
        return abi.encodePacked(r, s, v);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[_bound(seed, actors.length)];
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
