#!/usr/bin/env bash
# ============================================================
#  Exonerve :: One-Click Launcher (Linux / macOS)
#  Run:  bash run.sh
#  Installs deps if needed, starts the control plane, opens the
#  dashboard, and fires a few attacks so you can watch detection live.
# ============================================================
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CYAN='\033[96m'; GREEN='\033[92m'; RED='\033[91m'; RESET='\033[0m'
say(){ echo -e "${CYAN}  $1${RESET}"; }

echo ""
echo -e "${CYAN}  ========================================"
echo    "   EXONERVE  ::  starting up"
echo -e "  ========================================${RESET}"
echo ""

# --- Python check ---
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo -e "${RED}  [ERROR] Python not found.${RESET}"; exit 1; }

# --- install deps only if Flask is missing ---
if ! "$PY" -c "import flask" >/dev/null 2>&1; then
    say "Installing dependencies (first run only)..."
    "$PY" -m pip install -r requirements.txt --break-system-packages >/dev/null 2>&1 \
        || "$PY" -m pip install -r requirements.txt
fi

# --- start the control plane in the background ---
say "Starting the control plane..."
"$PY" host_control_plane/control_center.py > /tmp/exonerve_control.log 2>&1 &
CC_PID=$!
trap 'echo ""; say "Stopping control plane..."; kill $CC_PID 2>/dev/null' EXIT INT TERM

# --- wait until the web port is up ---
say "Waiting for the control plane to come online..."
for i in $(seq 1 20); do
    if "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.5);
sys.exit(0 if s.connect_ex(('127.0.0.1',5000))==0 else 1)" 2>/dev/null; then break; fi
    sleep 0.5
done

# --- open the dashboard ---
say "Opening the SOC dashboard..."
( xdg-open http://127.0.0.1:5000 >/dev/null 2>&1 \
  || open http://127.0.0.1:5000 >/dev/null 2>&1 \
  || say "Open your browser to http://127.0.0.1:5000" ) &

# --- fire a few attacks so the dashboard populates ---
sleep 1
echo ""; say "Firing sample attacks so you can watch detection happen live:"
for atk in ransomware cred_dump c2_beacon; do
    echo -e "${CYAN}    -> ${atk}${RESET}"
    "$PY" fire_attack.py --attack "$atk" >/dev/null 2>&1 || true
    sleep 1
done

echo ""
echo -e "${GREEN}  ========================================"
echo    "   Dashboard is LIVE:  http://127.0.0.1:5000"
echo -e "  ========================================${RESET}"
echo ""
say "Fire more attacks any time (new terminal):"
say "    $PY fire_attack.py --attack webshell"
say "    $PY fire_attack.py --list"
echo ""
say "Press Ctrl+C here to stop the control plane."
wait $CC_PID
