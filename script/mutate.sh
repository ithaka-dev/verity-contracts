#!/usr/bin/env bash
#
# Mutation testing: does the suite actually detect the bugs it is supposed to?
#
# ## Why this exists
#
# Coverage counts lines executed. It cannot tell an assertion from a bystander, and this repository
# has the receipt: the invariant suite once scored **2 of 12** — you could delete
# `requireValidSignature` outright and every test stayed green — while coverage looked healthy the
# whole time.
#
# So the real measure is: reintroduce a defect, and see whether anything fails. Each mutant below
# is a bug that was either found in review here, or is one edit away from a defect that was.
#
# ## Reading a result
#
# `killed` is good — the suite caught it. `SURVIVED` means that behaviour has no test behind it, so
# it can regress silently, which is exactly how the H-1 and H-2 findings shipped.
#
# **Do not delete a surviving mutant to make the score green.** Either write the test, or mark it
# EQUIVALENT with a reason — a mutant that cannot change observable behaviour is not a gap.
#
#   ./script/mutate.sh              # all mutants
#   ./script/mutate.sh --quick      # invariant suite only; faster, weaker
set -uo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.foundry/bin:$PATH"

QUICK=""
[ "${1:-}" = "--quick" ] && QUICK="--match-path test/invariant/*"

backup=$(mktemp -d)
cp -R src "$backup/"
restore() { rm -rf src && cp -R "$backup/src" src; }
trap 'restore; rm -rf "$backup"' EXIT

killed=0
survived=0
equivalent=0
declare -a survivors=()

# A mutant that fails to apply is worse than a missing one: it leaves the score looking complete
# while one behaviour went unchecked. `set -e` is off here so results can be tallied, so this exits
# explicitly instead.
mutate() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, pathlib
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
s = p.read_text()
if old not in s:
    sys.exit(f"PATTERN NOT FOUND in {path}: {old[:70]}")
p.write_text(s.replace(old, new, 1))
PY
  local status=$?
  if [ $status -ne 0 ]; then
    echo "::error::mutant could not be applied — the source moved and this mutant stopped testing" >&2
    exit 2
  fi
}

run() {
  local name="$1"
  find cache/invariant -type f -delete 2>/dev/null
  if forge test $QUICK >/dev/null 2>&1; then
    printf '  \033[31mSURVIVED\033[0m  %s\n' "$name"
    survivors+=("$name")
    survived=$((survived + 1))
  else
    printf '  killed    %s\n' "$name"
    killed=$((killed + 1))
  fi
  restore
}

note_equivalent() {
  printf '  equivalent %s\n             \033[2m%s\033[0m\n' "$1" "$2"
  equivalent=$((equivalent + 1))
}

echo "Mutation testing verity-contracts${QUICK:+ (quick)}"
echo

echo "— authorization —"
mutate src/LicenseToken.sol \
  'authorizer.requireValidSignature(hashMintAuthorization(auth), signature);' '' \
  && run "signature verification deleted"

mutate src/LicenseToken.sol \
  'if (auth.fromLicenseId != 0) {' 'if (false) {' \
  && run "H-1: mint accepts an upgrade authorization"

mutate src/LicenseToken.sol \
  'if (auth.fromLicenseId == 0) revert MintAuthorizationIsNotAnUpgrade();' '' \
  && run "H-2: upgrade accepts a mint authorization"

mutate src/LicenseToken.sol \
  'if (_nonceUsed[auth.manifest][auth.nonce]) {' 'if (false) {' \
  && run "nonce replay guard deleted"

mutate src/LicenseToken.sol \
  'revert RelayedUpgradeNotSupportedInMvp(msg.sender, auth.to);' '' \
  && run "relayed upgrade permitted"

mutate src/LicenseToken.sol \
  'if (block.timestamp > auth.expiry) {' 'if (false) {' \
  && run "expiry check deleted"

echo
echo "— entitlement model (ADR 0023, 0024) —"
mutate src/LicenseToken.sol \
  'if (balanceOf(msg.sender, auth.fromLicenseId) == 0) revert NotAHolder(auth.fromLicenseId);' '' \
  && run "upgrade without holding the source licence"

mutate src/LicenseToken.sol \
  'if (claimant != 0 && claimant != licenseId) {' 'if (false) {' \
  && run "instance claim is no longer permanent"

mutate src/LicenseToken.sol \
  'if (balanceOf(msg.sender, licenseId) == 0) {' 'if (false) {' \
  && run "anyone may bind any licence"

echo
echo "— developer terms (ADR 0004, 0022) —"
mutate src/LicenseToken.sol \
  'if (burned != auth.burnExpected) revert BurnTermChanged(auth.burnExpected, burned);' '' \
  && run "burn term may change after the sale"

mutate src/LicenseToken.sol \
  'if (!allowed) revert TransitionNotAllowed(from, auth.version);' '' \
  && run "unpriced transition permitted"

mutate src/LicenseToken.sol \
  'if (toIndex < fromIndex && !manifest.downgradesAllowed()) {' 'if (false) {' \
  && run "downgrade guard deleted"

mutate src/LicenseToken.sol \
  'if (fromIndex == toIndex) revert SameVersion(from);' '' \
  && run "upgrade to the same version permitted"

echo
echo "— manifest (I5, access control) —"
mutate src/AppManifest.sol \
  'if (_records[key].exists) revert VersionAlreadyPublished(version);' '' \
  && run "I5: published records may be overwritten"

mutate src/AppManifest.sol 'external onlyDeveloper {' 'external {' \
  && run "onlyDeveloper removed from a manifest write"

echo
echo "— known equivalent —"
note_equivalent "tokenIdFor via encodePacked" \
  "abi.encodePacked(address, bytes32) is injective: a 20-byte prefix cannot be re-split, so this
             cannot change behaviour. Kept in encode() form because it stops being injective the
             moment a second variable-width field is added."

echo
total=$((killed + survived))
echo "score: $killed/$total killed, $equivalent equivalent"

if [ "$survived" -gt 0 ]; then
  echo
  echo "these behaviours have no test behind them:"
  for s in "${survivors[@]}"; do echo "  - $s"; done
  echo
  echo "Write the test, or mark the mutant EQUIVALENT with a reason. Do not delete it."
  exit 1
fi

echo "every mutant was caught."
