// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "./AppManifest.sol";

/// @title AppManifestFactory
/// @notice A convenience for deploying an `AppManifest` at a predictable address. **Optional, and
/// deliberately powerless.**
///
/// @dev The reason this contract is worth being careful about: an app's identity is its manifest
/// address (ADR 0011), and a factory is the natural place for that to quietly become
/// *registration*. One `onlyOwner`, one fee, one allowlist, one `deployedByUs` mapping that another
/// contract starts consulting, and publishing an app now requires someone's cooperation — which is
/// exactly what spec §1 forbids.
///
/// So the guarantees here are structural rather than promised:
///
/// - **It holds no state.** There is no mapping of deployed manifests, no counter, no owner. There
///   is nothing to gate with, and nothing for another contract to consult as an authority.
/// - **`LicenseToken` does not know it exists.** It accepts any address that answers the
///   `IAppManifest` interface, so a manifest deployed with a bare `new AppManifest(developer)` is
///   indistinguishable from one deployed here and works identically.
/// - **The event is an observer's index, not a catalog.** Nothing reads it back on chain; an
///   indexer that wants to notice new apps may, and an app that is never indexed is no less real.
///
/// The test suite asserts the first and second of these, because they are the kind of property that
/// erodes by convenience rather than by decision.
///
/// ### Why full deployments and not minimal proxies
///
/// Clones would be cheaper, and would cost `AppManifest.developer` its `immutable` — a proxy has to
/// be initialised after deployment, which introduces both mutable authority and a window between
/// deploy and initialise. For the contract that decides who may publish versions of an app, a
/// developer address fixed in the bytecode at construction is worth more than the gas.
contract AppManifestFactory {
    /// @notice A manifest was deployed through this factory.
    /// @dev Emitted for indexers. Nothing on chain reads it.
    event AppManifestDeployed(
        address indexed manifest, address indexed developer, address indexed deployer, bytes32 salt
    );

    /// @notice Deploy an `AppManifest` at an address determined by the caller and `salt`.
    /// @param salt The caller's choice of salt.
    /// @param developer The account that may publish versions.
    /// @return manifest The deployed manifest, whose address is this app's identity.
    function deploy(bytes32 salt, address developer) external returns (address manifest) {
        manifest = address(new AppManifest{salt: _saltFor(msg.sender, salt)}(developer));
        emit AppManifestDeployed(manifest, developer, msg.sender, salt);
    }

    /// @notice The address `deploy` would produce.
    /// @dev Takes `deployer` explicitly because the effective salt is bound to the caller — see
    /// `_saltFor`.
    function predictAddress(address deployer, bytes32 salt, address developer)
        external
        view
        returns (address)
    {
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(AppManifest).creationCode, abi.encode(developer)));
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), address(this), _saltFor(deployer, salt), initCodeHash
                        )
                    )
                )
            )
        );
    }

    /// @dev The caller's salt is namespaced by the caller, so one developer's chosen addresses
    /// cannot be occupied by anyone else. Without this, a shared factory lets a bystander deploy to
    /// an address a developer has published in advance and intends to use.
    function _saltFor(address deployer, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(deployer, salt));
    }
}
