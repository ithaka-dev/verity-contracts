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
    /// **`fromLicenseId` is what distinguishes the two entry points, and it must stay in the signed
    /// payload.** Zero means a fresh mint; non-zero names the *specific licence* being transitioned
    /// away from, and only `upgrade` accepts it.
    ///
    /// It names a licence rather than a version because licences are per-unit (ADR 0023). An
    /// earlier revision named the version, which under fungible per-version ids meant "any unit of
    /// that version the caller happens to hold" — and that ambiguity ran all the way out to the app
    /// template, where a holder check could only establish that the signer was *a customer of this
    /// version*, never that they owned *this instance*.
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
        uint256 fromLicenseId;
        string version;
        address to;
        bool burnExpected;
        uint256 nonce;
        uint256 expiry;
    }

    bytes32 private constant _MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(address manifest,uint256 fromLicenseId,string version,address to,bool burnExpected,uint256 nonce,uint256 expiry)"
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
    /// @notice The caller does not hold the specific licence it is trying to upgrade.
    /// @dev A licence is one indivisible unit (ADR 0023), so this is ownership of *that* licence
    /// and not membership of the set of people holding that version.
    error NotAHolder(uint256 licenseId);
    /// @notice The developer has not priced this transition as permitted.
    error TransitionNotAllowed(string from, string to);
    /// @notice The transition moves to an earlier version and the developer forbids that.
    error DowngradesNotAllowed(string from, string to);
    /// @notice Source and destination are the same version.
    error SameVersion(string version);
    /// @notice An upgrade was submitted by someone other than the holder.
    /// @dev See `upgrade` for why this is a deliberate MVP boundary rather than an oversight.
    error RelayedUpgradeNotSupportedInMvp(address caller, address holder);
    /// @notice An authorization naming a `fromLicenseId` was submitted to `mint`.
    /// @dev The path that would let a holder keep both versions after paying an upgrade price.
    error UpgradeAuthorizationIsNotAMint(uint256 fromLicenseId);
    /// @notice The licence named by the authorization does not exist.
    error UnknownLicense(uint256 licenseId);
    /// @notice An authorization with no `fromVersion` was submitted to `upgrade`.
    error MintAuthorizationIsNotAnUpgrade();
    /// @notice The developer changed the burn term after this authorization was signed.
    error BurnTermChanged(bool signed, bool current);
    /// @notice The app has not appointed an account able to authorize minting.
    error NoMintAuthorizer(address manifest);
    /// @notice Nothing has ever been minted for this `tokenId`, so there is nothing to resolve.
    error UnknownToken(uint256 tokenId);
    /// @notice The caller does not hold the licence they are binding.
    error NotLicenseHolder(address caller, uint256 licenseId);
    /// @notice Another licence claimed this instance first, and a claim is permanent.
    error InstanceAlreadyClaimed(bytes32 instanceId, uint256 claimedBy);
    /// @notice An instance id of zero would compare equal to "unbound".
    error EmptyInstanceId();

    /// @notice A `tokenId` was resolved to its manifest and version for the first time.
    event TokenOriginRecorded(
        uint256 indexed tokenId, address indexed manifest, string version, bytes32 composeHash
    );
    /// @notice A licence was minted against an authorization.
    event LicenseMinted(
        uint256 indexed tokenId, address indexed to, address indexed manifest, string version
    );
    /// @notice A licence was bound to the instance it runs.
    event InstanceBound(
        uint256 indexed licenseId, bytes32 indexed instanceId, address indexed holder
    );
    /// @notice A holder moved between versions. Burn and mint happened in this one transaction.
    event LicenseUpgraded(
        address indexed holder,
        address indexed manifest,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool burned
    );

    mapping(uint256 licenseId => TokenOrigin origin) private _origin;

    /// @dev Which instance a licence runs. Rebindable by the holder — an instance can be destroyed,
    /// and the holder needs a path to a replacement.
    mapping(uint256 licenseId => bytes32 instanceId) private _instanceOf;

    /// @dev Which licence claimed an instance. **Effectively write-once, and that is the safety
    /// property.** `_instanceOf` is a convenience; this is what stops one holder from pointing their
    /// licence at another holder's running instance. Never cleared, so an instance the holder has
    /// moved on from still cannot be claimed by anyone else.
    mapping(bytes32 instanceId => uint256 licenseId) private _claimedBy;
    /// @dev Per-version mint counter. The next licence's serial is this plus one.
    mapping(uint256 versionId => uint256 minted) private _serial;
    mapping(address manifest => mapping(uint256 nonce => bool used)) private _nonceUsed;

    /// @dev The base URI is empty on purpose: `uri()` is overridden to resolve through to the
    /// manifest, so a stored template here would only ever be a stale second answer.
    constructor() ERC1155("") EIP712("Verity License", "1") {}

    // ---------------------------------------------------------------------------------------
    // Identity
    // ---------------------------------------------------------------------------------------

    /// @notice The identifier for a *version* of an app. Groups licences; is not one itself.
    ///
    /// @dev Kept as a pure function because it is what an off-chain reader uses to ask "which
    /// version is this licence for" without consulting any registry. **It is not a `tokenId`** —
    /// nothing is ever minted against it. That distinction is the whole of ADR 0023: an ERC-1155
    /// balance of a per-version id says only *"this address is a customer of this version"*, and a
    /// system that needs to know *"this address owns this instance"* cannot be built on it.
    ///
    /// `abi.encode` over `(address, bytes32)`, both fixed-width. `abi.encodePacked` would in fact
    /// be injective here — a 20-byte address prefix followed by a 32-byte hash cannot be re-split —
    /// so this is not fixing a live collision. It is chosen because the packed form stops being
    /// injective the moment a second variable-width field is added, and that edit would look
    /// harmless.
    function versionIdFor(address manifest, string memory version) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(manifest, keccak256(bytes(version)))));
    }

    /// @notice The identifier of the `serial`-th licence minted for a version.
    ///
    /// @dev Deterministic, so a holder can recompute their own licence id from the mint event, and
    /// distinct per unit, so `balanceOf(holder, licenseId)` answers ownership of one specific
    /// entitlement rather than membership of a crowd. Every licence has a balance of exactly 1.
    function licenseIdFor(address manifest, string memory version, uint256 serial)
        public
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(manifest, keccak256(bytes(version)), serial)));
    }

    /// @notice How many licences have been minted for a version. The next serial is this plus one.
    function mintedCount(address manifest, string calldata version)
        external
        view
        returns (uint256)
    {
        return _serial[versionIdFor(manifest, version)];
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
    // Instance binding
    // ---------------------------------------------------------------------------------------

    /// @notice Bind a licence to the instance it runs.
    ///
    /// @dev **Holding a licence is not the same as owning an instance, and this is where the second
    /// half comes from.**
    ///
    /// A licence says what its holder may run (ADR 0023). It cannot say *which* of several identical
    /// instances of the same version is theirs — several holders of the same version are
    /// indistinguishable from the outside, which is exactly what let one act on another's instance
    /// before per-unit ids landed. An app needs both answers, and only one of them was on chain.
    ///
    /// So the holder states it themselves, in their own transaction. **The orchestrator is not
    /// involved and cannot be**: it writes nothing to chain, which is a large part of what keeps it
    /// replaceable under spec §2.8. A binding written by the orchestrator would be discretion over
    /// who owns what, which is the thing invariant I3 exists to prevent.
    ///
    /// ### Why the instance claim is permanent and the licence binding is not
    ///
    /// `_claimedBy` is never cleared. An instance id, once claimed, belongs to that licence forever
    /// — so a holder cannot point their licence at somebody else's running instance, and cannot do
    /// it later by waiting for that holder to move on.
    ///
    /// `_instanceOf` is rebindable, because instances are destroyed and holders need a path to a
    /// replacement. Rebinding to a *fresh* instance is always allowed; rebinding to a *claimed* one
    /// never is.
    ///
    /// ### The residual, stated rather than hidden
    ///
    /// A fresh instance is unclaimed until someone claims it, so an attacker who learns its id
    /// before the holder binds can claim it first. What they get is a **denial of service on an
    /// empty instance** — the app serves nothing until bound, so there is no data to reach — and
    /// unlike the volume-based binding it replaced, the theft is a visible on-chain event the holder
    /// can check for before using the instance.
    ///
    /// Narrowing it further means not disclosing the instance id until it is bound, which is the
    /// orchestrator's redeem path rather than this contract.
    function bindInstance(uint256 licenseId, bytes32 instanceId) external {
        if (instanceId == bytes32(0)) revert EmptyInstanceId();
        if (balanceOf(msg.sender, licenseId) == 0) {
            revert NotLicenseHolder(msg.sender, licenseId);
        }

        uint256 claimant = _claimedBy[instanceId];
        if (claimant != 0 && claimant != licenseId) {
            revert InstanceAlreadyClaimed(instanceId, claimant);
        }

        _claimedBy[instanceId] = licenseId;
        _instanceOf[licenseId] = instanceId;
        emit InstanceBound(licenseId, instanceId, msg.sender);
    }

    /// @notice The instance a licence runs, or zero if it has not been bound.
    ///
    /// @dev **This is the question an app must ask**, alongside "does the signer hold this licence".
    /// Neither is sufficient alone: the first without the second lets a stranger act on a bound
    /// instance, and the second without the first lets any holder of the version act on any
    /// instance of it.
    function instanceOf(uint256 licenseId) external view returns (bytes32) {
        return _instanceOf[licenseId];
    }

    /// @notice The licence that claimed an instance, or zero. Permanent once set.
    function claimedBy(bytes32 instanceId) external view returns (uint256) {
        return _claimedBy[instanceId];
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
                    auth.fromLicenseId,
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
    function mint(MintAuthorization calldata auth, bytes calldata signature)
        external
        returns (uint256 licenseId)
    {
        if (auth.fromLicenseId != 0) {
            revert UpgradeAuthorizationIsNotAMint(auth.fromLicenseId);
        }
        _consumeAuthorization(auth, signature);
        licenseId = _issue(auth.manifest, auth.version, auth.to);
        emit LicenseMinted(licenseId, auth.to, auth.manifest, auth.version);
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
    function upgrade(MintAuthorization calldata auth, bytes calldata signature)
        external
        returns (uint256 licenseId)
    {
        if (msg.sender != auth.to) {
            revert RelayedUpgradeNotSupportedInMvp(msg.sender, auth.to);
        }
        if (auth.fromLicenseId == 0) revert MintAuthorizationIsNotAnUpgrade();

        // The source version comes from the licence being consumed, not from the message. A caller
        // cannot name one version and burn a licence for another, because there is only one licence
        // in play and it knows what it is.
        TokenOrigin memory source = _origin[auth.fromLicenseId];
        if (source.manifest == address(0)) revert UnknownLicense(auth.fromLicenseId);
        if (source.manifest != auth.manifest) revert UnknownLicense(auth.fromLicenseId);
        string memory from = source.version;

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

        // Ownership of *this* licence, not of the version. Under the previous per-version ids this
        // check passed for anyone holding any unit of that version (ADR 0023).
        if (balanceOf(msg.sender, auth.fromLicenseId) == 0) revert NotAHolder(auth.fromLicenseId);

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
            _burn(msg.sender, auth.fromLicenseId, 1);
        }

        licenseId = _issue(auth.manifest, auth.version, msg.sender);

        // The binding follows the holder across the upgrade. Without this, every upgrade would
        // strand the instance: the new licence would be unbound, and rebinding would be refused
        // because the old licence's claim on that instance is permanent. The holder would be locked
        // out of their own running instance by the act of upgrading it.
        //
        // Carrying it grants nothing new — it is the same holder, the same instance, and an upgrade
        // is already their own act on their own licence.
        bytes32 boundInstance = _instanceOf[auth.fromLicenseId];
        if (boundInstance != bytes32(0)) {
            _instanceOf[licenseId] = boundInstance;
            _claimedBy[boundInstance] = licenseId;
            delete _instanceOf[auth.fromLicenseId];
            emit InstanceBound(licenseId, boundInstance, msg.sender);
        }

        emit LicenseUpgraded(msg.sender, auth.manifest, auth.fromLicenseId, licenseId, burned);
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

    /// @dev Mint one new, uniquely-identified licence.
    ///
    /// Resolves the version against the manifest first — which reverts for an unknown one, so a
    /// licence can never exist for a version that was never published — then allocates the next
    /// serial and records what the id was derived from.
    ///
    /// Every licence has a balance of exactly 1. That is what makes `balanceOf(holder, licenseId)`
    /// an ownership question rather than a membership one.
    function _issue(address manifest, string calldata version, address to)
        private
        returns (uint256 licenseId)
    {
        IAppManifest.VersionRecord memory record = IAppManifest(manifest).versionRecord(version);

        uint256 versionId = versionIdFor(manifest, version);
        uint256 serial = _serial[versionId] + 1;
        _serial[versionId] = serial;

        licenseId = licenseIdFor(manifest, version, serial);
        _origin[licenseId] = TokenOrigin({manifest: manifest, version: version});
        emit TokenOriginRecorded(licenseId, manifest, version, record.composeHash);

        _mint(to, licenseId, 1, "");
    }
}
