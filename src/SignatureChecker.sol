// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

/// @title SignatureChecker
/// @notice The one place in this repository that verifies a signature.
///
/// @dev **Every signature check routes through here, and CI asserts that `ecrecover` appears
/// nowhere else.** That is not style: ADR 0005 requires account-related logic to be built for smart
/// accounts even while only the EOA branch is implemented, and the reason is that deployed
/// contracts are effectively immutable. A contract that calls `ecrecover` directly works perfectly
/// until a holder's account is an ERC-4337 wallet, and then it cannot be fixed.
///
/// The smart-account branch **reverts explicitly** rather than being absent. An absent branch is
/// indistinguishable from an unconsidered one, and a caller with a contract account deserves
/// "not supported yet" rather than "invalid signature" — those are different problems and only one
/// of them is theirs.
library SignatureChecker {
    /// @notice The signer is a contract account, which this version cannot verify.
    /// @param account The account that signed.
    error SmartAccountNotSupportedInMvp(address account);

    /// @notice The signature is not 65 bytes.
    /// @param length The length supplied.
    error MalformedSignature(uint256 length);

    /// @notice `s` is in the upper half of the curve order, so the signature is malleable.
    /// @dev Rejected because a malleable signature has a second valid encoding, which turns any
    /// signature-keyed replay guard into one that can be walked around once.
    error MalleableSignature();

    /// @notice `v` is neither 27 nor 28.
    error InvalidSignatureV(uint8 v);

    /// @notice `ecrecover` returned the zero address.
    /// @dev Its failure mode, and one that silently passes an `== expected` check if `expected` is
    /// also zero — so it is caught here rather than left to callers to remember.
    error InvalidSignature();

    /// secp256k1 curve order ÷ 2. Above this, `s` has an equivalent lower form.
    bytes32 private constant _HALF_CURVE_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Verify `signature` over `digest` was produced by `signer`.
    /// @dev Reverts rather than returning false. A boolean invites `if (ok)` with no else, and the
    /// else is the case that matters.
    /// @param signer The account that must have signed.
    /// @param digest The EIP-712 digest that was signed.
    /// @param signature A 65-byte `(r, s, v)` signature.
    function requireValidSignature(address signer, bytes32 digest, bytes calldata signature)
        internal
        view
    {
        if (signer.code.length > 0) {
            // ERC-1271 lives here. Deliberately not implemented in MVP (ADR 0002 defers account
            // abstraction), but the branch exists so the seam is real from the first commit and
            // adding it later is filling in a case rather than restructuring a contract.
            revert SmartAccountNotSupportedInMvp(signer);
        }
        if (signature.length != 65) revert MalformedSignature(signature.length);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (uint256(s) > uint256(_HALF_CURVE_ORDER)) revert MalleableSignature();
        if (v != 27 && v != 28) revert InvalidSignatureV(v);

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert InvalidSignature();
        if (recovered != signer) revert InvalidSignature();
    }

    /// @notice Whether `signer` is an account this version can verify at all.
    /// @dev Lets a caller distinguish "cannot verify this account type" from "signature was wrong"
    /// before attempting verification.
    function isSupportedAccount(address signer) internal view returns (bool) {
        return signer != address(0) && signer.code.length == 0;
    }
}
