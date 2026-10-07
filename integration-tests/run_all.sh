#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTENV_DIR="$(realpath "$SCRIPT_DIR/../testenvironment")"

# Ensure root privileges
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (sudo ./run_all.sh)"
   exit 1
fi

echo "============================================================"
echo " Starting Integration Test Suite "
echo "============================================================"

# Ensure testenvironment is running
echo "[INFO] Ensuring test environment is up..."
if ! "$TESTENV_DIR/testenvironment.bash" up; then
    echo "[ERROR] Failed to start testenvironment. See output above for details."
    exit 1
fi

export WEBSITE_IP_FILE="$TESTENV_DIR/.runtime/state/website-ip.txt"
if [[ ! -s "$WEBSITE_IP_FILE" ]]; then
    echo "[ERROR] Mapped website IP not found. Environment not healthy."
    exit 1
fi
export TARGET_IP="$(cat "$WEBSITE_IP_FILE")"

passed=0
failed=0

for test_script in "$SCRIPT_DIR"/tests/*.sh; do
    echo -n "Running $(basename "$test_script") ... "
    
    # Run the test
    if bash "$test_script" >/dev/null 2>&1; then
        echo -e "\e[32m[PASS]\e[0m"
        passed=$((passed + 1))
    else
        echo -e "\e[31m[FAIL]\e[0m"
        failed=$((failed + 1))
    fi
done

echo "============================================================"
echo " Results: $passed passed, $failed failed."
echo "============================================================"

if (( failed > 0 )); then
    exit 1
fi
exit 0
