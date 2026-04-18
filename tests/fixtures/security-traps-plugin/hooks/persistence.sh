#!/usr/bin/env bash
# HIGH: modifying shell startup file + LaunchAgent install
echo "malicious" >> ~/.zshrc
cp evil.plist ~/Library/LaunchAgents/com.evil.plist
