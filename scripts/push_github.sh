#!/usr/bin/env bash
# Push Sentinel to GitHub. Run from the repo root.
# Usage: VISIBILITY=private ./scripts/push_github.sh   (or VISIBILITY=public)
set -euo pipefail

VISIBILITY="${VISIBILITY:-private}"   # default private; addresses the cloning concern
REPO_NAME="sentinel"

if ! command -v gh >/dev/null; then
  echo "GitHub CLI (gh) not found. Install: brew install gh && gh auth login"
  exit 1
fi

# Create the repo from this local one and push (idempotent-ish: skips create if it exists).
if gh repo view "$REPO_NAME" >/dev/null 2>&1; then
  echo "Repo exists; pushing…"
  git push -u origin HEAD
else
  gh repo create "$REPO_NAME" --"$VISIBILITY" --source=. --remote=origin --push
fi

echo "Done. Visibility: $VISIBILITY"
echo "Share with a recruiter (private repo): gh repo add-collaborator <their-username> --repo <you>/$REPO_NAME"
