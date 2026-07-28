// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../src/AppManifest.sol";
import {AppManifestFactory} from "../src/AppManifestFactory.sol";
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

/// @title DeployAppManifest
/// @notice Publishes an app, by deploying its `AppManifest`.
///
/// @dev **Deploying this contract is publishing the app.** There is no subsequent registration step
/// and nothing to wait for (ADR 0011). The resulting address is the app's identity.
///
/// Uses `AppManifestFactory` when `VERITY_FACTORY` is set, purely so the address can be computed in
/// advance; deploying directly is equally valid and produces an identical app (ADR 0021). If that
/// ever stops being true, the factory has become a gatekeeper and the bug is there, not here.
///
/// ```sh
/// VERITY_DEVELOPER=0x... \
/// VERITY_SALT=my-app \
/// VERITY_FACTORY=0x...  # optional
/// forge script script/DeployAppManifest.s.sol:DeployAppManifest \
///   --rpc-url "$VERITY_RPC_URL" --account verity-developer --broadcast --verify
/// ```
contract DeployAppManifest is Script {
    function run() external returns (address manifest) {
        address developer = vm.envAddress("VERITY_DEVELOPER");
        address factory = vm.envOr("VERITY_FACTORY", address(0));
        bytes32 salt = keccak256(bytes(vm.envOr("VERITY_SALT", string(""))));

        if (factory == address(0)) {
            vm.startBroadcast();
            manifest = address(new AppManifest(developer));
            vm.stopBroadcast();
            console2.log("Deployed directly (no factory).");
        } else {
            address predicted =
                AppManifestFactory(factory).predictAddress(msg.sender, salt, developer);
            console2.log("Predicted address  ", predicted);

            vm.startBroadcast();
            manifest = AppManifestFactory(factory).deploy(salt, developer);
            vm.stopBroadcast();

            require(manifest == predicted, "factory deployed to an unexpected address");
        }

        console2.log("AppManifest        ", manifest);
        console2.log("developer          ", AppManifest(manifest).developer());
        console2.log("");
        console2.log("This address is the app's identity. Nothing else needs to happen.");
    }
}
