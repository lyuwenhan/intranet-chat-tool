#!/bin/bash
set -e
git fetch origin
if ! git diff --quiet HEAD origin/main; then
    echo "[Git] Remote has new commits, pulling..."
    git reset --hard HEAD
    git pull origin main
    npm install
else
    echo "[Git] Already up-to-date."
fi
