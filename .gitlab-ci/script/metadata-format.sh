#!/bin/bash

set -eu -o pipefail

# Fetch the target branch to ensure we have the history
git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"

# Get the list of commit SHAs in this MR
COMMITS=$(git rev-list "$CI_MERGE_REQUEST_DIFF_BASE_SHA".."$CI_COMMIT_SHA")

for SHA in $COMMITS; do
  echo "Checking format for commit ${SHA:0:8}"

  git log -1 --format=%B "$SHA" | awk '
  BEGIN {
      first_line = 0
      second_line_empty = 0
      body_count = 0
  }

  NR == 1 {
      # Line 1 must not be empty or whitespace-only
      if ($0 ~ /^[[:space:]]*$/) {
          print "Error: Line 1 (Subject/Header) is empty."
          exit 1
      }
      first_line = 1
      next
  }

  NR == 2 {
      # Line 2 must be completely empty (or whitespace-only)
      if ($0 !~ /^[[:space:]]*$/) {
          print "Error: Line 2 must be blank/empty."
          exit 1
      }
      second_line_empty = 1
      next
  }

  NR >= 3 {
      # Count non-empty lines in the remaining body
      if ($0 !~ /^[[:space:]]*$/) {
          body_count++
      }
  }

  END {
      # Check if we were interrupted by an earlier exit
      if (NR < 3) {
          print "Error: File must contain at least 3 lines."
	  print "First line: Subject"
	  print "Second line: Empty line"
	  print "Third and the following lines: Description"
          exit 1
      }

      # Ensure there is at least one non-empty line in the body
      if (body_count == 0) {
          print "Error: Body (line 3 onwards) must contain at least one non-empty line."
          exit 1
      }

      print "Validation passed!"
  }
  '
done
