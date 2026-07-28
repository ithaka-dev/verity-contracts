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
/// ### What this script checks, and what it still cannot
///
/// It checks that `imageDigest` textually appears in the compose. That is a substring test rather
/// than a parse — Solidity cannot read YAML — but it is enough to catch the case that matters: a
/// record naming a digest the compose does not reference produces a licence that fails ADR 0009
/// step 3 for every holder, permanently, with no edit path. Printing that as advice to a human
/// while holding the file in memory was the wrong division of labour.
///
/// The check is line-oriented rather than a substring search over the whole file, because a
/// substring search approves the exact thing it is supposed to catch. Measured: with a plain
/// `contains(digest)`, a compose with `image: ghcr.io/x/y:latest` and the licensed digest sitting
/// in a `#` comment above it published successfully — as did the same tagged image with the digest
/// in an unrelated `environment:` value. Anchoring on `sha256:` fixes neither, since both contain
/// that string too.
///
/// So it also enforces I8 directly: **every** `image:` line must carry a `sha256:` digest, and at
/// least one must carry the licensed one.
///
/// What it still cannot do is parse YAML. A pathological line that satisfies the text rules while
/// meaning something else in YAML would pass, so the publishing tool's pre-flight parse remains
/// the thorough check — and the verifier's cross-check on the holder's side remains the one a
/// publisher cannot route around.
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

        _assertComposePinsLicensedImage(string(compose), imageDigest);

        // A URI with no hash looks like a commitment and commits to nothing: the document behind an
        // unchanged URI can be swapped freely. Same defect as a tag-referenced image.
        if (bytes(metadataURI).length > 0 && metadataHash == bytes32(0)) {
            revert(
                "VERITY_METADATA_URI is set but VERITY_METADATA_FILE is not, so metadataHash would be zero"
            );
        }

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

        vm.startBroadcast();
        manifest.publishVersion(
            version, imageDigest, composeHash, composeURI, capabilities, metadataHash, metadataURI
        );
        vm.stopBroadcast();

        console2.log("");
        console2.log("Published. Licence holders on this version will run exactly this compose.");
    }

    /// @dev JSON forbids a raw newline inside a string, so the embedded compose always carries its
    /// line breaks as the two-character `\n` escape. Splitting on that is reliable in a way that
    /// splitting on a real newline would not be.
    function _assertComposePinsLicensedImage(string memory compose, bytes32 imageDigest)
        internal
        pure
    {
        string memory text = vm.toLowercase(compose);
        string memory wanted = string.concat(
            "sha256:", vm.replace(vm.toLowercase(vm.toString(imageDigest)), "0x", "")
        );

        string[] memory lines = vm.split(text, "\\n");
        bool sawLicensed = false;
        uint256 imageLines = 0;

        for (uint256 i = 0; i < lines.length; i++) {
            if (!vm.contains(lines[i], "image:")) continue;
            imageLines += 1;
            if (!vm.contains(lines[i], "sha256:")) {
                revert(string.concat("compose references an image by tag, not digest: ", lines[i]));
            }
            if (vm.contains(lines[i], wanted)) sawLicensed = true;
        }

        // A compose with nothing to check is not a compose that passed the check.
        if (imageLines == 0) revert("compose declares no images");
        if (!sawLicensed) {
            revert(string.concat("no image line references VERITY_IMAGE_DIGEST (", wanted, ")"));
        }
    }
}
