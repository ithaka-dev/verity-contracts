// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {IAppManifest} from "./IAppManifest.sol";
import {SignatureChecker} from "./SignatureChecker.sol";
import {ERC1155} from "openzeppelin-contracts/token/ERC1155/ERC1155.sol";
import {EIP712} from "openzeppelin-contracts/utils/cryptography/EIP712.sol";

/// @title LicenseToken
/// @notice The entitlement itself: an ERC-1155 balance saying which app version an account may run.
///
/// @dev **One contract for every app, and it is still not a registry.** A `tokenId` is
/// `keccak256(manifest, version)` — pure arithmetic over an address and a string, computable by
/// anyone, offline, before anything is deployed. No one writes an app into this contract to make its
/// licences exist, and no one can decline to. Deploying an `AppManifest` publishes an app (ADR
/// 0011); this contract only counts.
///
/// The `_origin` mapping below is the one thing that looks like a registry and is not: it is written
/// *by* the first mint, recording what a `tokenId` was derived from so `uri()` can walk back to the
/// manifest. It grants nothing and gates nothing. Removing it would cost metadata resolution and no
/// entitlement.
///
/// ### Where the money is, and is not
///
/// This contract collects no payment. Spec §4.2 and invariant I4 make the 402-gated resource *be*
/// the signed mint authorization: payment and entitlement are one act, settled off-chain, and what
/// arrives here is the receipt. `AppManifest.upgradePrice` is therefore the developer's published
/// price for the payment service to charge — this contract enforces the `allowed` half of that
/// answer and does not re-collect the `price` half.
contract LicenseToken is ERC1155, EIP712 {
    using SignatureChecker for address;

    /// @notice A signed statement that someone is entitled to mint one licence.
    /// @dev Signed by `IAppManifest.mintAuthorizer()` for `manifest` — read from the app's own
    /// contract, never from configuration here.
    struct MintAuthorization {
        address manifest;
        string version;
        address to;
        uint256 nonce;
        uint256 expiry;
    }

    bytes32 private constant _MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(address manifest,string version,address to,uint256 nonce,uint256 expiry)"
    );

    /// @notice What a `tokenId` was derived from.
    struct TokenOrigin {
        address manifest;
        string version;
    }

    /// @notice The authorization's `expiry` has passed.
    error AuthorizationExpired(uint256 expiry, uint256 blockTimestamp);
    /// @notice This `(manifest, nonce)` pair has already been used.
    error NonceAlreadyUsed(address manifest, uint256 nonce);
    /// @notice The caller holds none of the version it is trying to upgrade from.
    error NotAHolder(uint256 tokenId);
    /// @notice The developer has not priced this transition as permitted.
    error TransitionNotAllowed(string from, string to);
    /// @notice The transition moves to an earlier version and the developer forbids that.
    error DowngradesNotAllowed(string from, string to);
    /// @notice Source and destination are the same version.
    error SameVersion(string version);
    /// @notice An upgrade was submitted by someone other than the holder.
    /// @dev See `upgrade` for why this is a deliberate MVP boundary rather than an oversight.
    error RelayedUpgradeNotSupportedInMvp(address caller, address holder);
    /// @notice Nothing has ever been minted for this `tokenId`, so there is nothing to resolve.
    error UnknownToken(uint256 tokenId);

    /// @notice A `tokenId` was resolved to its manifest and version for the first time.
    event TokenOriginRecorded(
        uint256 indexed tokenId, address indexed manifest, string version, bytes32 composeHash
    );
    /// @notice A licence was minted against an authorization.
    event LicenseMinted(
        uint256 indexed tokenId, address indexed to, address indexed manifest, string version
    );
    /// @notice A holder moved between versions. Burn and mint happened in this one transaction.
    event LicenseUpgraded(
        address indexed holder,
        address indexed manifest,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool burned
    );

    mapping(uint256 tokenId => TokenOrigin origin) private _origin;
    mapping(address manifest => mapping(uint256 nonce => bool used)) private _nonceUsed;

    /// @dev The base URI is empty on purpose: `uri()` is overridden to resolve through to the
    /// manifest, so a stored template here would only ever be a stale second answer.
    constructor() ERC1155("") EIP712("Verity License", "1") {}

    // ---------------------------------------------------------------------------------------
    // Identity
    // ---------------------------------------------------------------------------------------

    /// @notice The `tokenId` for a version of an app.
    /// @dev `abi.encode`, not `abi.encodePacked` — packed encoding of a dynamic type lets two
    /// different `(manifest, version)` pairs collide, and a collision here means one app's licence
    /// entitles a holder to run another's.
    function tokenIdFor(address manifest, string memory version) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(manifest, keccak256(bytes(version)))));
    }

    /// @notice What a `tokenId` was derived from, if anything has been minted for it.
    function originOf(uint256 tokenId) external view returns (TokenOrigin memory) {
        TokenOrigin memory origin = _origin[tokenId];
        if (origin.manifest == address(0)) revert UnknownToken(tokenId);
        return origin;
    }

    /// @notice Resolve token metadata *through* to the app's manifest.
    /// @dev The manifest is the authority on what a version is, so this contract stores no metadata
    /// of its own and cannot drift from it. A developer publishing a version publishes its metadata
    /// in the same act.
    function uri(uint256 tokenId) public view override returns (string memory) {
        TokenOrigin memory origin = _origin[tokenId];
        if (origin.manifest == address(0)) revert UnknownToken(tokenId);
        return IAppManifest(origin.manifest).versionRecord(origin.version).metadataURI;
    }

    // ---------------------------------------------------------------------------------------
    // Minting
    // ---------------------------------------------------------------------------------------

    /// @notice The EIP-712 digest a `mintAuthorizer` must sign.
    /// @dev Public so the payment service signs exactly what this contract will check, rather than
    /// reimplementing the encoding and discovering the difference in production.
    function hashMintAuthorization(MintAuthorization calldata auth) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _MINT_AUTHORIZATION_TYPEHASH,
                    auth.manifest,
                    keccak256(bytes(auth.version)),
                    auth.to,
                    auth.nonce,
                    auth.expiry
                )
            )
        );
    }

    /// @notice Whether a `(manifest, nonce)` pair has been spent.
    function nonceUsed(address manifest, uint256 nonce) external view returns (bool) {
        return _nonceUsed[manifest][nonce];
    }

    /// @notice Mint one licence against an authorization signed by the app's mint authorizer.
    /// @dev Anyone may submit: nothing of the recipient's is consumed, so a relayer paying gas for
    /// a holder is fine here. `upgrade` is different, and says why.
    function mint(MintAuthorization calldata auth, bytes calldata signature) external {
        _consumeAuthorization(auth, signature);
        uint256 tokenId = _recordOrigin(auth.manifest, auth.version);
        _mint(auth.to, tokenId, 1, "");
        emit LicenseMinted(tokenId, auth.to, auth.manifest, auth.version);
    }

    /// @notice Move a holder from one version to another: burn the old entitlement and mint the new
    /// one in a single transaction.
    ///
    /// @dev **Atomic by construction, which is the point** (ADR 0008). There is no window in which
    /// the holder has both, so spec §2.9's one-licence-one-instance rule needs no exemption for
    /// upgrades, and no window in which they have neither, so a transaction that reverts half way
    /// cannot leave someone holding nothing.
    ///
    /// This does not touch a running VM and does not migrate anything. Upgrade is `AppManifest`
    /// bookkeeping (ADR 0004); migration is a separate, holder-signed act (I10) and minting is not
    /// consent to it.
    ///
    /// **Why the holder must submit.** Burning is destructive, and the authorization is signed by
    /// the *mint authorizer*, not by the holder — so on its own it is the seller's consent to sell,
    /// never the holder's consent to give up what they have. Requiring `msg.sender == auth.to`
    /// supplies the missing consent as the cheapest possible signal. A relayed path needs a
    /// holder-signed struct, which is deferred with account abstraction (ADR 0002) and rejected
    /// explicitly here rather than approximated (ADR 0005). Note this excludes third-party
    /// relayers, not smart accounts: an ERC-4337 account executing this call *is* `msg.sender`.
    function upgrade(
        string calldata from,
        MintAuthorization calldata auth,
        bytes calldata signature
    ) external {
        if (msg.sender != auth.to) revert RelayedUpgradeNotSupportedInMvp(msg.sender, auth.to);

        IAppManifest manifest = IAppManifest(auth.manifest);

        uint256 fromIndex = manifest.versionIndex(from);
        uint256 toIndex = manifest.versionIndex(auth.version);
        if (fromIndex == 0) revert TransitionNotAllowed(from, auth.version);
        if (fromIndex == toIndex) revert SameVersion(from);
        if (toIndex < fromIndex && !manifest.downgradesAllowed()) {
            revert DowngradesNotAllowed(from, auth.version);
        }

        (, bool allowed) = manifest.upgradePrice(from, auth.version);
        if (!allowed) revert TransitionNotAllowed(from, auth.version);

        uint256 fromTokenId = tokenIdFor(auth.manifest, from);
        if (balanceOf(msg.sender, fromTokenId) == 0) revert NotAHolder(fromTokenId);

        _consumeAuthorization(auth, signature);

        bool burned = manifest.burnOnUpgrade();
        if (burned) {
            _burn(msg.sender, fromTokenId, 1);
        }

        uint256 toTokenId = _recordOrigin(auth.manifest, auth.version);
        _mint(msg.sender, toTokenId, 1, "");

        emit LicenseUpgraded(msg.sender, auth.manifest, fromTokenId, toTokenId, burned);
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    /// @dev Checks expiry, spends the nonce, then verifies the signature. Spending before verifying
    /// is deliberate: the nonce is spent for every path that reaches the signature check, so a
    /// caller cannot probe signatures against a nonce they can keep reusing.
    function _consumeAuthorization(MintAuthorization calldata auth, bytes calldata signature)
        private
    {
        // A validator can nudge `block.timestamp` by seconds. An authorization expiry is minutes to
        // hours, so seconds of slack buys an attacker a marginally longer window on a signature the
        // authorizer already issued to that recipient — not a different outcome. The alternative,
        // block numbers, prices the window in a unit the signing service cannot reason about.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > auth.expiry) {
            revert AuthorizationExpired(auth.expiry, block.timestamp);
        }
        if (_nonceUsed[auth.manifest][auth.nonce]) {
            revert NonceAlreadyUsed(auth.manifest, auth.nonce);
        }
        _nonceUsed[auth.manifest][auth.nonce] = true;

        address authorizer = IAppManifest(auth.manifest).mintAuthorizer();
        authorizer.requireValidSignature(hashMintAuthorization(auth), signature);
    }

    /// @dev Resolves the version against the manifest — which reverts for an unknown one, so a
    /// licence can never be minted for a version that was never published — and remembers the
    /// derivation the first time a `tokenId` is used.
    function _recordOrigin(address manifest, string calldata version)
        private
        returns (uint256 tokenId)
    {
        IAppManifest.VersionRecord memory record = IAppManifest(manifest).versionRecord(version);
        tokenId = tokenIdFor(manifest, version);
        if (_origin[tokenId].manifest == address(0)) {
            _origin[tokenId] = TokenOrigin({manifest: manifest, version: version});
            emit TokenOriginRecorded(tokenId, manifest, version, record.composeHash);
        }
    }
}
