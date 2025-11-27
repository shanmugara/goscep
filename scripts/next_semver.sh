#!/usr/bin/env bash
set -euo pipefail

# returns next semantic patch tag, e.g. v0.0.6
# Usage: ./scripts/next_semver.sh [--dry-run]
DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

# Get latest tag that looks like vMAJOR.MINOR.PATCH
latest=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n1 || true)

if [[ -z "$latest" ]]; then
  next="v0.0.1"
else
  # strip leading 'v'
  ver=${latest#v}
  IFS='.' read -r major minor patch <<< "$ver"
  # sanity check integers
  if ! [[ $major =~ ^[0-9]+$ && $minor =~ ^[0-9]+$ && $patch =~ ^[0-9]+$ ]]; then
    echo "Latest tag ($latest) is not semantic; fallback to v0.0.1" >&2
    next="v0.0.1"
  else
    patch=$((patch + 1))
    next="v${major}.${minor}.${patch}"
  fi
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "DRY RUN: would use $next"
else
  echo "$next"
fi
