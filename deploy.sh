#!/usr/bin/env bash
# =============================================================================
# Exonerve :: Deployment Script
# =============================================================================
# Installs and configures Exonerve on either the Host Control Plane
# or inside the Guest Production VM.
#
# Usage:
#   sudo bash deploy.sh host    — Install Control Center on host machine
#   sudo bash deploy.sh guest   — Install Sentry Agent inside guest VM
#
# Requirements:
#   - Ubuntu 22.04 / Debian 12 / RHEL 9 / Rocky 9
#   - Python 3.9+
#   - Root/sudo access
# =============================================================================

set -euo pipefail

ROLE="${1:-}"
INSTALL_BASE="/opt/exonerve"
SERVICE_USER="exonerve"
PYTHON="python3"

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; DIM='\033[2m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✓ ${1}${RESET}"; }
info() { echo -e "${CYAN}  → ${1}${RESET}"; }
warn() { echo -e "${YELLOW}  ! ${1}${RESET}"; }
die()  { echo -e "${RED}  ✗ ${1}${RESET}"; exit 1; }

if [[ "$ROLE" != "host" && "$ROLE" != "guest" ]]; then
    echo -e "${CYAN}"
    echo "  EXONERVE DEPLOYMENT SCRIPT"
    echo -e "${RESET}"
    echo "  Usage: sudo bash deploy.sh [host|guest]"
    echo ""
    echo "    host  — Install Host Control Plane (VLAN 20)"
    echo "            Runs: control_center.py + hypervisor_api.py"
    echo "            SOC Dashboard available on http://0.0.0.0:5000"
    echo ""
    echo "    guest — Install Sentry Agent (VLAN 10 Guest VM)"
    echo "            Runs: sentry_agent.py (silent, no listening ports)"
    echo ""
    exit 1
fi

[[ $EUID -ne 0 ]] && die "Run as root (sudo bash deploy.sh $ROLE)"

echo -e "${CYAN}"
echo "   ███████╗██╗  ██╗ ██████╗ ███╗   ██╗███████╗██████╗ ██╗   ██╗███████╗ "
echo "   ██╔════╝╚██╗██╔╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗██║   ██║██╔════╝ "
echo "   █████╗   ╚███╔╝ ██║   ██║██╔██╗ ██║█████╗  ██████╔╝██║   ██║█████╗   "
echo "   ██╔══╝   ██╔██╗ ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝   "
echo "   ███████╗██╔╝ ██╗╚██████╔╝██║ ╚████║███████╗██║  ██║ ╚████╔╝ ███████╗ "
echo "   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝ "
echo -e "${RESET}"
echo "  Out-of-Band Cyber Resilience Framework — Deployment: ${CYAN}${ROLE^^}${RESET}"
echo ""

# ---- Prerequisites ----
info "Checking system prerequisites..."
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install it first."
command -v pip3    >/dev/null 2>&1 || { apt-get install -y python3-pip 2>/dev/null || yum install -y python3-pip 2>/dev/null || die "pip3 not found."; }
PYTHON_VER=$($PYTHON --version 2>&1 | awk '{print $2}')
ok "Python $PYTHON_VER found"

# ---- Create install directory ----
info "Creating install directory: $INSTALL_BASE"
mkdir -p "$INSTALL_BASE"

# ---- Create service user (host only) ----
if [[ "$ROLE" == "host" ]]; then
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
        ok "Created system user: $SERVICE_USER"
    else
        ok "System user already exists: $SERVICE_USER"
    fi
fi

# ---- Copy files ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$ROLE" == "host" ]]; then
    info "Installing Host Control Plane files..."
    cp -r "$SCRIPT_DIR/host_control_plane/"* "$INSTALL_BASE/host_control_plane/" 2>/dev/null || {
        mkdir -p "$INSTALL_BASE/host_control_plane/forensics_archive"
        cp "$SCRIPT_DIR/host_control_plane/control_center.py"  "$INSTALL_BASE/host_control_plane/"
        cp "$SCRIPT_DIR/host_control_plane/hypervisor_api.py"  "$INSTALL_BASE/host_control_plane/"
        cp "$SCRIPT_DIR/host_control_plane/requirements.txt"   "$INSTALL_BASE/host_control_plane/"
    }
    # New v2 host files
    cp "$SCRIPT_DIR/host_control_plane/failover_orchestrator.py" "$INSTALL_BASE/host_control_plane/" 2>/dev/null || true
    cp "$SCRIPT_DIR/host_control_plane/dashboard.html"           "$INSTALL_BASE/host_control_plane/" 2>/dev/null || true
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_BASE"

    # Shared crypto module (both roles need it)
    mkdir -p "$INSTALL_BASE/common"
    cp "$SCRIPT_DIR/common/"*.py "$INSTALL_BASE/common/" 2>/dev/null || true
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_BASE/common"

    # Generate the shared master secret (once) for the authenticated channel.
    mkdir -p /etc/exonerve
    if [[ ! -f /etc/exonerve/master.env ]]; then
        MASTER_HEX="$($PYTHON -c 'import os;print(os.urandom(32).hex())')"
        echo "EXONERVE_MASTER_KEY=${MASTER_HEX}" > /etc/exonerve/master.env
        chmod 600 /etc/exonerve/master.env
        ok "Generated master key: /etc/exonerve/master.env (mode 600)"
        warn "Copy this SAME file to every guest VM at /etc/exonerve/master.env"
        echo -e "  ${CYAN}${MASTER_HEX}${RESET}"
    else
        info "Master key already present at /etc/exonerve/master.env"
    fi

    # Config file
    if [[ ! -f "$INSTALL_BASE/host_control_plane/hypervisor_config.json" ]]; then
        cp "$SCRIPT_DIR/host_control_plane/hypervisor_config.example.json" \
           "$INSTALL_BASE/host_control_plane/hypervisor_config.json"
        warn "Created default hypervisor_config.json — EDIT IT before starting the service!"
    fi

    # Install Python deps
    info "Installing Python dependencies..."
    pip3 install -r "$INSTALL_BASE/host_control_plane/requirements.txt" --quiet
    ok "Dependencies installed"

    # Install and enable systemd service
    info "Installing systemd service..."
    cp "$SCRIPT_DIR/host_control_plane/exonerve-control.service" /etc/systemd/system/
    # Patch install path if non-default
    sed -i "s|/opt/exonerve|${INSTALL_BASE}|g" /etc/systemd/system/exonerve-control.service
    systemctl daemon-reload
    systemctl enable exonerve-control.service
    ok "Systemd service installed: exonerve-control.service"

    echo ""
    echo -e "${GREEN}  ══════════════════════════════════════════════════════"
    echo -e "  ✓ Host Control Plane installation complete!"
    echo -e "  ══════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  Next steps:"
    echo -e "    1. Edit: ${CYAN}${INSTALL_BASE}/host_control_plane/hypervisor_config.json${RESET}"
    echo -e "    2. Start: ${CYAN}sudo systemctl start exonerve-control${RESET}"
    echo -e "    3. Dashboard: ${CYAN}http://$(hostname -I | awk '{print $1}'):5000${RESET}"
    echo -e "    4. Logs: ${CYAN}sudo journalctl -u exonerve-control -f${RESET}"
    echo ""

elif [[ "$ROLE" == "guest" ]]; then
    info "Installing Sentry Agent files..."
    mkdir -p "$INSTALL_BASE/guest_production_vm"
    cp "$SCRIPT_DIR/guest_production_vm/sentry_agent.py"  "$INSTALL_BASE/guest_production_vm/"
    cp "$SCRIPT_DIR/guest_production_vm/requirements.txt" "$INSTALL_BASE/guest_production_vm/"

    # Shared crypto module (agent needs it for the authenticated channel)
    mkdir -p "$INSTALL_BASE/common"
    cp "$SCRIPT_DIR/common/"*.py "$INSTALL_BASE/common/" 2>/dev/null || true

    # Master key reminder
    mkdir -p /etc/exonerve
    if [[ ! -f /etc/exonerve/master.env ]]; then
        warn "No /etc/exonerve/master.env found on this guest."
        warn "Copy it from the Control Center host — agent telemetry will be"
        warn "REJECTED until the guest shares the same master key."
    fi

    # Install Python deps
    info "Installing Python dependencies..."
    pip3 install -r "$INSTALL_BASE/guest_production_vm/requirements.txt" --quiet
    ok "Dependencies installed (psutil)"

    # Install systemd service
    info "Installing systemd service..."
    cp "$SCRIPT_DIR/guest_production_vm/exonerve-sentry.service" /etc/systemd/system/

    # Prompt for controller IP
    echo ""
    read -r -p "  Enter Control Center IP (VLAN 20, e.g. 192.168.20.1): " CTRL_IP
    CTRL_IP="${CTRL_IP:-192.168.20.1}"
    sed -i "s|192.168.20.1|${CTRL_IP}|g" /etc/systemd/system/exonerve-sentry.service
    sed -i "s|/opt/exonerve|${INSTALL_BASE}|g" /etc/systemd/system/exonerve-sentry.service

    read -r -p "  Enter target directory to monitor (default: /home): " TARGET_DIR
    TARGET_DIR="${TARGET_DIR:-/home}"
    sed -i "s|--target-dir /home|--target-dir ${TARGET_DIR}|g" /etc/systemd/system/exonerve-sentry.service

    systemctl daemon-reload
    systemctl enable exonerve-sentry.service
    ok "Systemd service installed: exonerve-sentry.service"

    echo ""
    echo -e "${GREEN}  ══════════════════════════════════════════════════════"
    echo -e "  ✓ Sentry Agent installation complete!"
    echo -e "  ══════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  Next steps:"
    echo -e "    1. Start: ${CYAN}sudo systemctl start exonerve-sentry${RESET}"
    echo -e "    2. Verify (should be silent): ${CYAN}sudo systemctl status exonerve-sentry${RESET}"
    echo -e "    3. Watch control plane dashboard for heartbeat confirmation"
    echo ""
fi
