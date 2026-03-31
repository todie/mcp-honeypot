#!/usr/bin/env bash
# Create a new release: bump version, update changelog, tag, and push.
#
# Usage:
#   ./scripts/release.sh patch   # 0.1.0 → 0.1.1
#   ./scripts/release.sh minor   # 0.1.0 → 0.2.0
#   ./scripts/release.sh major   # 0.1.0 → 1.0.0
#   ./scripts/release.sh 0.2.0   # explicit version
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CURRENT=$(cat VERSION | tr -d '[:space:]')
BUMP="${1:-}"

if [ -z "$BUMP" ]; then
    echo "Usage: ./scripts/release.sh <patch|minor|major|VERSION>"
    echo "Current version: $CURRENT"
    exit 1
fi

# Parse current version
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$BUMP" in
    patch) NEW="$MAJOR.$MINOR.$((PATCH + 1))" ;;
    minor) NEW="$MAJOR.$((MINOR + 1)).0" ;;
    major) NEW="$((MAJOR + 1)).0.0" ;;
    *)     NEW="$BUMP" ;;
esac

echo "==> Bumping version: $CURRENT → $NEW"

# Update VERSION file
echo "$NEW" > VERSION

# Update Helm chart version
if [ -f helm/Chart.yaml ]; then
    sed -i "s/^version:.*/version: $NEW/" helm/Chart.yaml
    sed -i "s/^appVersion:.*/appVersion: \"$NEW\"/" helm/Chart.yaml
    echo "    Updated helm/Chart.yaml"
fi

# Update CHANGELOG.md — replace [Unreleased] header with new version + date
# Uses printf for portable newline handling (BSD sed on macOS doesn't support \n)
DATE=$(date +%Y-%m-%d)
NL=$'\n'
sed -i "s/## \[Unreleased\]/## [Unreleased]${NL}${NL}## [$NEW] - $DATE/" CHANGELOG.md
# Update the compare links at the bottom
sed -i "s|\[Unreleased\]:.*|[Unreleased]: https://github.com/todie/mcp-honeypot/compare/v$NEW...HEAD${NL}[$NEW]: https://github.com/todie/mcp-honeypot/compare/v$CURRENT...v$NEW|" CHANGELOG.md
echo "    Updated CHANGELOG.md"

# Commit and tag
git add VERSION CHANGELOG.md helm/Chart.yaml 2>/dev/null || true
git commit -m "Release v$NEW"
git tag -a "v$NEW" -m "Release v$NEW"

echo ""
echo "==> Release v$NEW prepared"
echo "    To publish:"
echo "      git push origin main --tags"
echo "      gh release create v$NEW --generate-notes"
echo ""
echo "    Or to undo:"
echo "      git reset --soft HEAD~1 && git tag -d v$NEW"
