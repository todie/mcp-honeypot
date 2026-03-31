#!/usr/bin/env bash
# Set up branch protection rules on main via GitHub API
set -euo pipefail

REPO="todie/mcp-honeypot"
BRANCH="main"

echo "==> Setting branch protection on $REPO/$BRANCH"

gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Lint (ruff)",
      "Type-check (pyright)",
      "Tests (pytest)"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true,
  "required_conversation_resolution": false
}
EOF

echo "==> Branch protection applied:"
echo "    - PRs required (0 approvals — solo dev)"
echo "    - CI must pass (lint + typecheck + test)"
echo "    - Strict status checks (branch must be up-to-date)"
echo "    - Force push disabled"
echo "    - Linear history required"
