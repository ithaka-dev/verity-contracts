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

    /// @notice A signed statement that someone is entitled to one licence.
    /// @dev Signed by `IAppManifest.mintAuthorizer()` for `manifest` — read from the app's own
    /// contract, never from configuration here.
    ///
    /// **`fromVersion` is what distinguishes the two entry points, and it must stay in the signed
    /// payload.** Empty means a fresh mint; non-empty names the version being transitioned away
    /// from, and only `upgrade` accepts it.
    ///
    /// An earlier revision omitted this, and the omission made every check in `upgrade`
    /// decorative. If one struct authorizes both operations, an authorization issued for an
    /// upgrade replays into `mint`, where `burnOnUpgrade`, `downgradesAllowed` and
    /// `upgradePrice(...).allowed` are simply not consulted: a holder pays a discounted upgrade
    /// price and keeps both versions, which is two concurrent instances under spec §2.9 for the
    /// price of one transition. It does not even need the holder's cooperation — the signature is
    /// public in the mempool, so a bystander can front-run `mint` with it and defeat the
    /// developer's burn setting on someone else's behalf.
    ///
    /// Likewise the transition *source* is signed rather than passed alongside. `upgradePrice` is
    /// directional by design (ADR 0004), so a caller free to choose `from` picks the cheapest
    /// priced transition and burns the least valuable thing they hold — paying a recent-holder
    /// discount while keeping the version that discount was priced against.
    struct MintAuthorization {
        address manifest;
        string fromVersion;
        string version;
        address to;
        bool burnExpected;
        uint256 nonce;
        uint256 expiry;
    }

    bytes32 private constant _MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(address manifest,string fromVersion,string version,address to,bool burnExpected,uint256 nonce,uint256 expiry)"
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
    /// @notice An authorization naming a `fromVersion` was submitted to `mint`.
    /// @dev The path that would let a holder keep both versions after paying an upgrade price.
    error UpgradeAuthorizationIsNotAMint(string fromVersion);
    /// @notice An authorization with no `fromVersion` was submitted to `upgrade`.
    error MintAuthorizationIsNotAnUpgrade();
    /// @notice The developer changed the burn term after this authorization was signed.
    error BurnTermChanged(bool signed, bool current);
    /// @notice The app has not appointed an account able to authorize minting.
    error NoMintAuthorizer(address manifest);
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
    /// @dev `abi.encode` over `(address, bytes32)`, both fixed-width.
    ///
    /// `abi.encodePacked` would in fact be injective *here* — a 20-byte address prefix followed by
    /// a 32-byte hash cannot be re-split — so this is not fixing a live collision. It is chosen
    /// because the packed form stops being injective the moment a second variable-width field is
    /// added, and that edit would look harmless. A collision in this function means one app's
    /// licence entitles a holder to run another's.
    function tokenIdFor(address manifest, string memory version) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(manifest, keccak256(bytes(version)))));
    }

    /// @notice What a `tokenId` was derived from, if anything has been minted for it.
    ///
    /// @dev **This is a display convenience and never an authority. Do not start a trust decision
    /// here.**
    ///
    /// `auth.manifest` is caller-supplied, so anyone can deploy a contract that answers the
    /// `IAppManifest` interface, name itself as its own mint authorizer, and mint themselves a
    /// licence. Inside this contract that is harmless — every `tokenId` is namespaced by the
    /// manifest address, so a hostile app is confined to ids no real app can occupy, and it cannot
    /// mint, burn or collide with anyone else's.
    ///
    /// The hazard is entirely downstream. A consumer that resolves *`tokenId` → `originOf` →
    /// manifest → `composeHash`* is reading attacker-authored values out of genuine on-chain
    /// state — satisfying invariant I3 to the letter while being told what to run by the attacker.
    ///
    /// Resolution must run the other way: start from a manifest address the caller already trusts,
    /// compute `tokenIdFor(manifest, version)`, and check the holder's balance. That direction
    /// cannot be redirected, because the id is derived from the trusted address rather than
    /// recovered from an untrusted one.
    function originOf(uint256 tokenId) external view returns (TokenOrigin memory) {
        TokenOrigin memory origin = _origin[tokenId];
        if (origin.manifest == address(0)) revert UnknownToken(tokenId);
        return origin;
    }

    /// @notice Resolve token metadata *through* to the app's manifest.
    /// @dev The manifest is the authority on what a version is, so this contract stores no metadata
    /// of its own and cannot drift from it. A developer publishing a version publishes its metadata
    /// in the same act.
    ///
    /// Carries the same caveat as `originOf`: the manifest reached here came from whoever minted
    /// the token, so the string returned is only as trustworthy as that address. It is also an
    /// unbounded external call into code the caller did not choose — a hostile manifest can revert
    /// or return a very large string, which is harmless on chain and worth a timeout off it.
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
                    keccak256(bytes(auth.fromVersion)),
                    keccak256(bytes(auth.version)),
                    auth.to,
                    auth.burnExpected,
                    auth.nonce,
                    auth.expiry
                )
            )
        );
    }

    /// @notice Whether a `(manifest, nonce)` pair has been spent.
    /// @dev Keyed on the **manifest, not the signer**, so the space is shared across successive
    /// authorizers. A developer who minted for themselves and later delegated to a payment service
    /// leaves used numbers behind, and a service starting its own counter at zero will collide with
    /// them. Harmless — the collision reverts and a different nonce works — but it is the natural
    /// implementation, so integrators should draw nonces randomly or seed above the high-water mark.
    function nonceUsed(address manifest, uint256 nonce) external view returns (bool) {
        return _nonceUsed[manifest][nonce];
    }

    /// @notice Mint one licence against an authorization signed by the app's mint authorizer.
    /// @dev Anyone may submit: nothing of the recipient's is consumed, so a relayer paying gas for
    /// a holder is fine here. `upgrade` is different, and says why.
    ///
    /// Refuses an authorization that names a `fromVersion`. Without that refusal this function is
    /// a way to spend an upgrade authorization while skipping everything `upgrade` enforces.
    function mint(MintAuthorization calldata auth, bytes calldata signature) external {
        if (bytes(auth.fromVersion).length != 0) {
            revert UpgradeAuthorizationIsNotAMint(auth.fromVersion);
        }
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
    function upgrade(MintAuthorization calldata auth, bytes calldata signature) external {
        if (msg.sender != auth.to) revert RelayedUpgradeNotSupportedInMvp(msg.sender, auth.to);
        if (bytes(auth.fromVersion).length == 0) revert MintAuthorizationIsNotAnUpgrade();

        string calldata from = auth.fromVersion;
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

        // The economic terms the holder paid for are part of what they were sold, so they belong
        // in the signature rather than being read from mutable state at execution time. Without
        // this, a developer who priced an upgrade at `burnOnUpgrade = false` — deliberately giving
        // away concurrency, and charging for it — can front-run the holder's transaction with
        // `setBurnOnUpgrade(true)` and burn the licence the holder just paid to keep.
        //
        // `downgradesAllowed` and `upgradePrice(...).allowed` are read late too, but both fail
        // safe: flipping them reverts the upgrade. Only this one destroys something.
        bool burned = manifest.burnOnUpgrade();
        if (burned != auth.burnExpected) revert BurnTermChanged(auth.burnExpected, burned);
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

    /// @dev Checks expiry, marks the nonce, then verifies the signature.
    ///
    /// The ordering carries no security weight and should not be read as if it did: a failed
    /// signature reverts the whole transaction, so the nonce write is rolled back with everything
    /// else. What actually prevents replay is that a *successful* call persists the mark, and the
    /// nonce is part of the signed payload.
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
        // Zero means the app has a contract developer and has not yet nominated an EOA to sign for
        // it. Named explicitly, because `ecrecover` returning zero on a malformed signature would
        // otherwise compare equal to it and mint.
        if (authorizer == address(0)) revert NoMintAuthorizer(auth.manifest);
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
