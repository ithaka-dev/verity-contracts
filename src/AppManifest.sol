// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {IAppManifest} from "./IAppManifest.sol";

/// @title AppManifest
/// @notice One per app. Holds the append-only version history and the developer's upgrade
/// economics.
///
/// @dev **This contract's address IS the app's identity** (ADR 0011). There is no registry, no
/// registration step and no mapping anyone writes — deploying this contract is publishing an app.
/// That is what makes spec §1's no-gatekeeper property structural rather than a policy someone
/// maintains: there is nothing here to gate.
///
/// Nothing in this contract reaches a running VM. Upgrade logic is entitlement bookkeeping
/// (ADR 0004); the orchestrator acts on chain state, and it upgrades in place (ADR 0008).
contract AppManifest is IAppManifest {
    /// @inheritdoc IAppManifest
    function CAPABILITY_HEALTH() external pure returns (uint256) {
        return 1 << 0;
    }

    /// @inheritdoc IAppManifest
    function CAPABILITY_MIGRATE() external pure returns (uint256) {
        return 1 << 1;
    }

    /// @inheritdoc IAppManifest
    function CAPABILITY_EXPORT() external pure returns (uint256) {
        return 1 << 2;
    }

    /// @notice Only the developer may write.
    error NotDeveloper(address caller);
    /// @notice The nominated account is a contract, which cannot sign in MVP.
    error SmartAccountNotSupportedInMvp(address account);
    /// @notice A version already exists and entries are append-only (I5).
    /// @dev Immutability is the point: a developer must not be able to change what a version means
    /// after someone has licensed it.
    error VersionAlreadyPublished(string version);
    /// @notice No such version.
    error UnknownVersion(string version);
    /// @notice A record field that must be set was zero.
    error EmptyField(string field);
    /// @notice The only account that may publish versions or set the knobs.
    /// @dev Immutable, with **no transfer path and no recovery**. Losing this key permanently ends
    /// the app's ability to publish new versions or change `mintAuthorizer`; already-published
    /// versions keep working forever, and every existing holder is unaffected.
    ///
    /// That follows from ADR 0011 — if the manifest address is the app's identity, a transferable
    /// developer is a transferable app, and "who may publish as this app" becomes a thing that can
    /// be sold or stolen. Belongs in developer-facing documentation rather than being discovered.
    address public immutable developer;

    /// @notice Whose signature authorizes minting this app's licences. Defaults to the developer.
    /// @dev The delegation a developer performs when a payment service mints on their behalf
    /// (spec §4.2). Kept here rather than in `LicenseToken` so the token contract holds no per-app
    /// configuration of its own — it reads authority out of the app's own contract, which is what
    /// keeps "there is no registry" true (ADR 0011).
    address public mintAuthorizer;

    uint256 private _versionCount;

    mapping(bytes32 versionKey => VersionRecord record) private _records;
    mapping(bytes32 transitionKey => uint256 price) private _upgradePrice;
    mapping(bytes32 transitionKey => bool allowed) private _upgradeAllowed;

    /// @notice Whether the old entitlement is burned when a new one mints.
    /// @dev Defaults to true. Not burning grants an additional runnable instance under spec §2.9's
    /// one-licence-one-instance rule, so a developer offering free minor versions without burning
    /// is giving away concurrency — usually without meaning to.
    bool public burnOnUpgrade = true;

    /// @notice Whether transitions to an older version are permitted.
    /// @dev Rollback is this contract's business, not the protocol's (ADR 0004). Note that backward
    /// state migration is not realistic — a previous version cannot read what a later one wrote —
    /// so a holder rolling back gets the old version with fresh state.
    bool public downgradesAllowed;

    modifier onlyDeveloper() {
        if (msg.sender != developer) revert NotDeveloper(msg.sender);
        _;
    }

    constructor(address developer_) {
        if (developer_ == address(0)) revert EmptyField("developer");
        developer = developer_;
        mintAuthorizer = developer_;
    }

    /// @notice Delegate mint authorization to another account, or take it back.
    /// @dev Rejects a contract account here rather than letting every later mint fail. ADR 0002
    /// defers ERC-1271, so a developer delegating to a multisig or a contract-based payment service
    /// would otherwise set this successfully and discover only at the first mint that nothing for
    /// their app can ever be minted. Failing at the setter puts the error where the mistake was.
    /// This restriction lifts when ERC-1271 lands in `SignatureChecker`.
    function setMintAuthorizer(address authorizer) external onlyDeveloper {
        if (authorizer == address(0)) revert EmptyField("mintAuthorizer");
        if (authorizer.code.length > 0) revert SmartAccountNotSupportedInMvp(authorizer);
        mintAuthorizer = authorizer;
        emit MintAuthorizerSet(authorizer);
    }

    /// @notice Append a version. Cannot overwrite (I5).
    function publishVersion(
        string calldata version,
        bytes32 imageDigest,
        bytes32 composeHash,
        string calldata composeURI,
        uint256 capabilities,
        bytes32 metadataHash,
        string calldata metadataURI
    ) external onlyDeveloper {
        bytes32 key = _key(version);
        if (_records[key].exists) revert VersionAlreadyPublished(version);
        if (bytes(version).length == 0) revert EmptyField("version");
        if (composeHash == bytes32(0)) revert EmptyField("composeHash");
        // Required because the verifier cross-checks the compose against it. A record without one
        // would leave that check with nothing to compare, which is the check ADR 0007 calls the
        // only enforcement an attacker cannot route around.
        if (imageDigest == bytes32(0)) revert EmptyField("imageDigest");
        // Without a retrievable compose, a verifier cannot compute the expected measurement at all.
        if (bytes(composeURI).length == 0) revert EmptyField("composeURI");

        _versionCount += 1;
        _records[key] = VersionRecord({
            imageDigest: imageDigest,
            composeHash: composeHash,
            composeURI: composeURI,
            capabilities: capabilities,
            metadataHash: metadataHash,
            metadataURI: metadataURI,
            index: _versionCount,
            exists: true
        });

        emit VersionPublished(version, composeHash, imageDigest);
    }

    /// @notice Price a transition between two versions.
    /// @dev Directional, which is what makes a downgrade expressible as a transition where `to` is
    /// older. `allowed` is separate from a zero price because free and forbidden are different.
    function setUpgradePrice(string calldata from, string calldata to, uint256 price, bool allowed)
        external
        onlyDeveloper
    {
        if (!_records[_key(from)].exists) revert UnknownVersion(from);
        if (!_records[_key(to)].exists) revert UnknownVersion(to);
        bytes32 key = _transitionKey(from, to);
        _upgradePrice[key] = price;
        _upgradeAllowed[key] = allowed;
        emit UpgradePriceSet(from, to, price, allowed);
    }

    /// @notice Set whether upgrading burns the old entitlement.
    function setBurnOnUpgrade(bool burn) external onlyDeveloper {
        burnOnUpgrade = burn;
        emit BurnOnUpgradeSet(burn);
    }

    /// @notice Set whether downgrades are permitted.
    function setDowngradesAllowed(bool allowed) external onlyDeveloper {
        downgradesAllowed = allowed;
        emit DowngradesAllowedSet(allowed);
    }

    /// @inheritdoc IAppManifest
    function versionRecord(string calldata version) external view returns (VersionRecord memory) {
        VersionRecord memory record = _records[_key(version)];
        if (!record.exists) revert UnknownVersion(version);
        return record;
    }

    /// @notice Whether a version exists, without reverting.
    function versionExists(string calldata version) external view returns (bool) {
        return _records[_key(version)].exists;
    }

    /// @inheritdoc IAppManifest
    function versionIndex(string calldata version) external view returns (uint256) {
        return _records[_key(version)].index;
    }

    /// @notice How many versions have been published.
    function versionCount() external view returns (uint256) {
        return _versionCount;
    }

    /// @inheritdoc IAppManifest
    function upgradePrice(string calldata from, string calldata to)
        external
        view
        returns (uint256 price, bool allowed)
    {
        bytes32 key = _transitionKey(from, to);
        return (_upgradePrice[key], _upgradeAllowed[key]);
    }

    /// @notice Whether a version declares a capability.
    function hasCapability(string calldata version, uint256 capability)
        external
        view
        returns (bool)
    {
        VersionRecord memory record = _records[_key(version)];
        if (!record.exists) revert UnknownVersion(version);
        return record.capabilities & capability == capability;
    }

    function _key(string calldata version) private pure returns (bytes32) {
        return keccak256(bytes(version));
    }

    function _transitionKey(string calldata from, string calldata to)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(keccak256(bytes(from)), keccak256(bytes(to))));
    }
}
