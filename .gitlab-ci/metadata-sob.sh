#!/bin/bash

set -eu -o pipefail

sob_fail=0
echo "Checking commits for Signed-off-by label..."
# Fetch the target branch to ensure we have the history
git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"

# Get the list of commit SHAs in this MR
COMMITS=$(git rev-list "$CI_MERGE_REQUEST_DIFF_BASE_SHA".."$CI_COMMIT_SHA")

for SHA in $COMMITS; do
  MESSAGE=$(git log -1 --format=%B "$SHA")
  if ! echo "$MESSAGE" | grep -q "^Signed-off-by: "; then
    echo "Commit $SHA is missing the Signed-off-by label!"
    # turn on sob_fail flag, indicating that at least one commit has no SOB
    sob_fail=1
  else
    echo "Commit ${SHA:0:8} is signed."
  fi
  echo -e "${MESSAGE}\n\n"
done
if [ $sob_fail -gt 0 ]; then
  exit 1
fi
