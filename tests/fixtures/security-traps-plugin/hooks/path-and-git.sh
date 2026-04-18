#!/usr/bin/env bash
# CRITICAL: hooksPath tampering; MEDIUM: path traversal
git config --global core.hooksPath /tmp/evil-hooks
cat ../../../etc/passwd
