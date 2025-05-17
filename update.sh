#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ " $* " == *" -f "* ]]; then
    echo "[Git] Checking for updates at $(date)"
    git fetch origin main
    if ! git diff --quiet HEAD origin/main; then
        echo "[Git] Remote has new commits. Pulling..."
        git reset --hard HEAD
        git pull --rebase --autostash origin main
    else
        echo "[Git] Already up-to-date."
        exit 1
    fi
else
    git fetch origin
    git reset --hard origin/main
fi
echo "[Git] Running npm install..."
npm install --no-audit --no-fund --prefer-offline
chmod u+x ./*.sh
chmod g+x ./*.sh
g++ judge/judge.cpp -o judge/judge.out -O2