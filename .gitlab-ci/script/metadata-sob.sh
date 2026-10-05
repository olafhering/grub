#!/bin/bash

set -eu -o pipefail

sob_fail=0

# Simple SOB regex, currently matching the presense of SOB (case sensitive) and the format
#
#     Signed-off-by: NAME LASTNAME <USER@DOMAIN.TOPLEVELDOMAIN>
#
SOB_FORMAT="Signed-off-by: NAME LASTNAME <USER@DOMAIN.TOPLEVELDOMAIN>"
SOB_REGEX='^Signed-off-by:[[:space:]]+[^<>[:space:]].*<[^[:space:]<>@]+@[^[:space:]<>@]+\.[^[:space:]<>@]+>\s*$'

echo "Checking commits for Signed-off-by label..."
echo "Expected format: $SOB_FORMAT"

# Fetch the target branch to ensure we have the history
git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"

# Get the list of commit SHAs in this MR
COMMITS=$(git rev-list "$CI_MERGE_REQUEST_DIFF_BASE_SHA".."$CI_COMMIT_SHA")

for SHA in $COMMITS; do
    MESSAGE=$(git log -1 --format=%B "$SHA")
    if ! echo "$MESSAGE" | grep -q "^Signed-off-by: "; then
	echo "Signed-off-by trailer missing on commit ${SHA:0:8}"
	sob_fail=1
    elif ! echo "$MESSAGE" | grep -iEq "$SOB_REGEX"; then
	echo "Wrong Signed-off-by format on commit ${SHA:0:8}"
	sob_fail=1
    else
	echo -e "Commit ${SHA:0:8} correctly signed it"
    fi
done

if [ $sob_fail -gt 0 ]; then
    exit 1
fi
