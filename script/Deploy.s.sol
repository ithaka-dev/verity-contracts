// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifestFactory} from "../src/AppManifestFactory.sol";
import {LicenseToken} from "../src/LicenseToken.sol";
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

/// @title Deploy
/// @notice Deploys the two chain-wide contracts: `LicenseToken` and `AppManifestFactory`.
///
/// @dev These are deployed once per chain and are **not** per-app. Deploying an app is deploying an
/// `AppManifest` — see `DeployAppManifest.s.sol`, or just call `new AppManifest(developer)`, which
/// is equally valid (ADR 0021).
///
/// Neither contract has an owner, an admin, or an upgrade path. There is no post-deployment
/// configuration step, which is deliberate: a deployment that needs configuring has a window in
/// which it is deployed and wrong.
///
/// ### Signing
///
/// `vm.startBroadcast()` takes no key. The signer comes from the `forge script` invocation —
/// `--account <keystore>` or a hardware wallet — so no private key is read by this script, written
/// into a file, or present in a shell history. Per `CLAUDE.md` C5, operator keys are never handed
/// to an agent; keeping the key outside the script is what makes that enforceable rather than
/// merely intended.
///
/// ```sh
/// forge script script/Deploy.s.sol:Deploy \
///   --rpc-url "$VERITY_RPC_URL" \
///   --account verity-deployer \
///   --broadcast --verify
/// ```
contract Deploy is Script {
    function run() external returns (LicenseToken token, AppManifestFactory factory) {
        vm.startBroadcast();
        token = new LicenseToken();
        factory = new AppManifestFactory();
        vm.stopBroadcast();

        console2.log("LicenseToken       ", address(token));
        console2.log("AppManifestFactory ", address(factory));
        console2.log("");
        console2.log("Neither contract has an owner. Nothing further needs configuring.");
    }
}
