#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"  # 切换到脚本所在目录，避免 cron 中路径错乱

echo "[Git] Checking for updates at $(date)"


git fetch origin
git reset --hard origin/main
echo "[Git] Running npm install..."
npm install --no-audit --no-fund --prefer-offline
chmod u+x ./*.sh
chmod g+x ./*.sh
g++ judge/judge.cpp -o judge/judge.out -O2