// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {SignatureChecker} from "../src/SignatureChecker.sol";
import {Test} from "forge-std/Test.sol";

/// A contract account, for asserting the smart-account branch is reached rather than absent.
contract ContractAccount {
    // Deliberately empty: what matters is that it has code.
}

/// Thin wrapper so a library `internal` function can be called across a `vm.expectRevert`.
contract Harness {
    function check(address signer, bytes32 digest, bytes calldata signature) external view {
        SignatureChecker.requireValidSignature(signer, digest, signature);
    }

    function supported(address signer) external view returns (bool) {
        return SignatureChecker.isSupportedAccount(signer);
    }
}

contract SignatureCheckerTest is Test {
    Harness internal harness;
    uint256 internal signerKey = 0xA11CE;
    address internal signer;

    function setUp() public {
        harness = new Harness();
        signer = vm.addr(signerKey);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    // — the happy path —

    function test_acceptsValidSignature() public view {
        bytes32 digest = keccak256("verity");
        harness.check(signer, digest, _sign(signerKey, digest));
    }

    function testFuzz_acceptsAnyValidSignature(bytes32 digest, uint248 keySeed) public view {
        uint256 key = uint256(keySeed) + 1; // non-zero, in range
        vm.assume(key < type(uint128).max);
        address who = vm.addr(key);
        harness.check(who, digest, _sign(key, digest));
    }

    // — the smart-account seam (ADR 0005) —

    /// The branch must be *reached and explicit*, not absent. A contract account should be told
    /// "not supported" rather than "invalid signature": those are different problems, and only one
    /// of them belongs to the caller.
    function test_contractAccountRevertsExplicitly() public {
        ContractAccount account = new ContractAccount();
        bytes32 digest = keccak256("verity");
        bytes memory signature = _sign(signerKey, digest);

        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureChecker.SmartAccountNotSupportedInMvp.selector, address(account)
            )
        );
        harness.check(address(account), digest, signature);
    }

    /// A contract account must never fall through to the EOA path — even if someone produced a
    /// signature that would recover to its address.
    function test_contractAccountNeverFallsThroughToEoaVerification() public {
        ContractAccount account = new ContractAccount();
        bytes32 digest = keccak256("verity");
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureChecker.SmartAccountNotSupportedInMvp.selector, address(account)
            )
        );
        harness.check(address(account), digest, _sign(signerKey, digest));
    }

    function test_isSupportedAccountDistinguishesAccountTypes() public {
        assertTrue(harness.supported(signer), "EOA is verifiable");
        assertFalse(harness.supported(address(new ContractAccount())), "contract account is not");
        assertFalse(harness.supported(address(0)), "zero address is not an account");
    }

    // — refusals —

    function test_rejectsWrongSigner() public {
        bytes32 digest = keccak256("verity");
        address other = vm.addr(0xB0B);
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        harness.check(other, digest, _sign(signerKey, digest));
    }

    function test_rejectsWrongDigest() public {
        bytes memory signature = _sign(signerKey, keccak256("verity"));
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        harness.check(signer, keccak256("something else"), signature);
    }

    function test_rejectsMalformedLength() public {
        vm.expectRevert(abi.encodeWithSelector(SignatureChecker.MalformedSignature.selector, 64));
        harness.check(signer, keccak256("verity"), new bytes(64));
    }

    /// A malleable signature has a second valid encoding, which would let one authorisation be
    /// replayed under a different signature — walking around any replay guard keyed on the
    /// signature bytes.
    function test_rejectsMalleableSignature() public {
        bytes32 digest = keccak256("verity");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);

        // Flip to the equivalent upper-half form: s' = n - s, v flipped.
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 flippedS = bytes32(n - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        vm.expectRevert(SignatureChecker.MalleableSignature.selector);
        harness.check(signer, digest, abi.encodePacked(r, flippedS, flippedV));
    }

    function test_rejectsInvalidV() public {
        bytes32 digest = keccak256("verity");
        (, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        vm.expectRevert(abi.encodeWithSelector(SignatureChecker.InvalidSignatureV.selector, 29));
        harness.check(signer, digest, abi.encodePacked(r, s, uint8(29)));
    }

    /// `ecrecover` returns zero on failure, which silently satisfies `== expected` when the
    /// expected address is also zero. Caught here so callers do not have to remember it.
    function test_zeroSignerIsNeverAccepted() public {
        bytes32 digest = keccak256("verity");
        bytes memory garbage = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(27));
        vm.expectRevert();
        harness.check(address(0), digest, garbage);
    }

    function testFuzz_randomBytesNeverVerify(bytes32 digest, bytes32 r, bytes32 s, uint8 v) public {
        vm.assume(v == 27 || v == 28);
        vm.assume(
            uint256(s)
                <= uint256(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
        );
        address recovered = ecrecover(digest, v, r, s);
        vm.assume(recovered != signer);
        vm.expectRevert(SignatureChecker.InvalidSignature.selector);
        harness.check(signer, digest, abi.encodePacked(r, s, v));
    }
}
