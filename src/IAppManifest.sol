// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

/// @title IAppManifest
/// @notice The per-app version registry: what each version is, and what it costs to move between
/// versions.
interface IAppManifest {
    /// @notice What a licence binds to.
    /// @dev The licence binds to `composeHash`, not `imageDigest` (ADR 0006). The platform measures
    /// the whole configuration, so a check against the image alone passes the right image running
    /// in a wrong environment. `imageDigest` stays in the record because it is what a verifier
    /// cross-checks the compose against — the one enforcement an attacker cannot route around.
    struct VersionRecord {
        bytes32 imageDigest;
        bytes32 composeHash;
        string composeURI;
        uint256 capabilities;
        bytes32 metadataHash;
        string metadataURI;
        /// @dev 1-based publication order; 0 means the version does not exist.
        ///
        /// Present because "is this transition a downgrade?" has to be answerable on chain, and a
        /// contract cannot compare version *strings* — `"1.10.0"` sorts below `"1.9.0"` as text, and
        /// nothing obliges a developer to use semver at all. Publication order is the only ordering
        /// this contract actually observes, and append-only publishing (I5) makes it monotonic for
        /// free.
        uint256 index;
        bool exists;
    }

    /// @notice Capability bits an app declares.
    /// @dev A bitmap, never an enum tier: capabilities have no natural ordering — an app could
    /// implement `migrate` without `health` — and bits extend without renumbering.
    function CAPABILITY_HEALTH() external pure returns (uint256);
    function CAPABILITY_MIGRATE() external pure returns (uint256);
    function CAPABILITY_EXPORT() external pure returns (uint256);

    event VersionPublished(string indexed version, bytes32 composeHash, bytes32 imageDigest);
    event UpgradePriceSet(string from, string to, uint256 price, bool allowed);
    event BurnOnUpgradeSet(bool burn);
    event DowngradesAllowedSet(bool allowed);
    event MintAuthorizerSet(address authorizer);

    function developer() external view returns (address);

    /// @notice Whose signature `LicenseToken` accepts as authorization to mint this app's licences.
    /// @dev Read from the app's own manifest rather than configured in the token contract, so a
    /// developer delegating to a payment service is an on-chain act of theirs — not a setting an
    /// operator flips. Defaults to the developer.
    function mintAuthorizer() external view returns (address);

    function versionRecord(string calldata version) external view returns (VersionRecord memory);

    /// @notice 1-based publication order, or 0 if the version does not exist.
    function versionIndex(string calldata version) external view returns (uint256);

    function upgradePrice(string calldata from, string calldata to)
        external
        view
        returns (uint256 price, bool allowed);
    function burnOnUpgrade() external view returns (bool);
    function downgradesAllowed() external view returns (bool);
}
