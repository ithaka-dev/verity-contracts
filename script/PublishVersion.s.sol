// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {AppManifest} from "../src/AppManifest.sol";
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

/// @title PublishVersion
/// @notice Appends a version to an app's manifest.
///
/// @dev **This is irreversible.** Version records are append-only (I5) because a developer must not
/// be able to change what a version means after someone has licensed it. There is no edit and no
/// delete; a mistake is corrected by publishing a further version and living with the wrong one
/// existing forever.
///
/// ### The compose hash is computed here, never supplied
///
/// `composeHash` is `sha256(app-compose.json)` over the exact bytes that will be served, and this
/// script computes it from the file rather than accepting it as a parameter. That is the whole
/// point: a hash typed by a human is a hash that can be typed wrong, and a wrong `composeHash` in a
/// published record produces a licence that can never be satisfied by any deployment — every
/// holder's verifier refuses, permanently, and the record cannot be edited.
///
/// The file passed here must be **byte-identical** to what `composeURI` serves. Not equivalent, not
/// re-serialised — identical. A pretty-printer between the two silently changes the hash.
///
/// ### What this script cannot check
///
/// That every image inside the compose is digest-pinned rather than tagged (I8, ADR 0007), and that
/// `imageDigest` actually appears among them. Solidity cannot parse YAML. Run the publishing tool's
/// pre-flight check first — a tag-referenced compose keeps `composeHash` stable while the code
/// inside it changes freely, so every check downstream passes while the guarantee is gone.
///
/// ```sh
/// VERITY_MANIFEST=0x... \
/// VERITY_VERSION=1.0.0 \
/// VERITY_COMPOSE_FILE=./app-compose.json \
/// VERITY_COMPOSE_URI=ipfs://bafy... \
/// VERITY_IMAGE_DIGEST=0x...        # the sha256 hex from the image's digest, 0x-prefixed
/// VERITY_CAPABILITIES=3            # bitmap: 1 health | 2 migrate | 4 export
/// VERITY_METADATA_URI=ipfs://...
/// forge script script/PublishVersion.s.sol:PublishVersion \
///   --rpc-url "$VERITY_RPC_URL" --account verity-developer --broadcast
/// ```
contract PublishVersion is Script {
    function run() external {
        AppManifest manifest = AppManifest(vm.envAddress("VERITY_MANIFEST"));
        string memory version = vm.envString("VERITY_VERSION");
        string memory composeFile = vm.envString("VERITY_COMPOSE_FILE");
        string memory composeURI = vm.envString("VERITY_COMPOSE_URI");
        bytes32 imageDigest = vm.envBytes32("VERITY_IMAGE_DIGEST");
        uint256 capabilities = vm.envOr("VERITY_CAPABILITIES", uint256(0));
        string memory metadataURI = vm.envOr("VERITY_METADATA_URI", string(""));

        bytes memory compose = vm.readFileBinary(composeFile);
        // sha256, not keccak256: this must match what the platform measures into MR-CONFIG-ID and
        // what the verifier recomputes. Using the wrong hash function here would produce a record
        // that looks entirely well-formed and can never be satisfied.
        bytes32 composeHash = sha256(compose);
        // Hashes the metadata *content*, not its URI. Hashing the URI would produce a value that
        // looks like a commitment and commits to nothing — the document behind an unchanged URI can
        // be replaced freely, which is the same defect as a tag-referenced image (I8).
        string memory metadataFile = vm.envOr("VERITY_METADATA_FILE", string(""));
        bytes32 metadataHash =
            bytes(metadataFile).length > 0 ? sha256(vm.readFileBinary(metadataFile)) : bytes32(0);

        if (manifest.versionExists(version)) {
            revert(
                string.concat(
                    "version '", version, "' is already published and records are append-only (I5)"
                )
            );
        }

        console2.log("manifest       ", address(manifest));
        console2.log("developer      ", manifest.developer());
        console2.log("version        ", version);
        console2.log("compose file   ", composeFile);
        console2.log("compose bytes  ", compose.length);
        console2.log("composeHash    ", vm.toString(composeHash));
        console2.log("composeURI     ", composeURI);
        console2.log("imageDigest    ", vm.toString(imageDigest));
        console2.log("capabilities   ", capabilities);
        console2.log("metadataURI    ", metadataURI);
        console2.log("");
        console2.log("Every holder who licenses this version binds to composeHash above.");
        console2.log("This record cannot be edited or removed once published.");
        console2.log("");
        console2.log("Confirm before broadcasting:");
        console2.log(" - the file above is byte-identical to what composeURI serves");
        console2.log(" - every image in it is pinned by digest, not by tag (I8)");
        console2.log(" - imageDigest appears among those pinned images");

        vm.startBroadcast();
        manifest.publishVersion(
            version, imageDigest, composeHash, composeURI, capabilities, metadataHash, metadataURI
        );
        vm.stopBroadcast();

        console2.log("");
        console2.log("Published. Licence holders on this version will run exactly this compose.");
    }
}
