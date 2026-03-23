#!/bin/bash
# Run gitleaks on staged files before commit
# Install: ln -sf ../../scripts/pre-commit-secret-scan.sh .git/hooks/pre-commit
if command -v gitleaks &> /dev/null; then
  gitleaks protect --staged --no-banner
  if [ $? -ne 0 ]; then
    echo "Secret detected in staged files. Commit blocked."
    exit 1
  fi
fi
