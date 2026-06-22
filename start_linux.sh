#!/bin/bash
# ============================================================
#  CyberGuard IDS v4 — Linux/macOS Startup Script
# ============================================================
echo ""
echo " =================================================="
echo "  🛡️  CyberGuard IDS v4 - Starting..."
echo " =================================================="
echo ""

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo " [ERROR] python3 not found!"
    echo "         Install: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON="python3"

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo " [*] Creating virtual environment..."
    $PYTHON -m venv venv
    if [ $? -ne 0 ]; then
        echo " [ERROR] Failed to create venv. Try: sudo apt install python3-venv"
        exit 1
    fi
fi

# Activate venv
source venv/bin/activate
PYTHON="python"

echo " [*] Installing/updating dependencies..."
pip install -r requirements.txt -q --disable-pip-version-check

# .env setup reminder
if [ ! -f ".env" ]; then
    echo ""
    echo " [!] No .env file found."
    echo " [!] Run setup wizard for Telegram/Email alerts:"
    echo "     $PYTHON backend/setup_wizard.py"
    echo " [!] Or copy manually: cp .env.example .env"
    echo ""
fi

# Check models
if [ ! -f "backend/models/xgb_model.pkl" ]; then
    echo ""
    echo " ================================================================"
    echo "  ⚠️  ML MODELS NOT FOUND — Training Required"
    echo " ================================================================"
    echo "  Train models now to enable detection:"
    echo "    python backend/train.py --fast"
    echo " ================================================================"
    echo ""
    read -p " Train now with fast mode? (y/n): " choice
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        echo " [*] Starting fast training..."
        $PYTHON backend/train.py --fast
        if [ $? -ne 0 ]; then
            echo " [!] Training failed. Check dataset files."
        fi
    fi
fi

echo ""
echo " =================================================="
echo "  Dashboard: http://localhost:5000"
echo "  Live capture needs root: sudo ./start_linux.sh"
echo "  Press Ctrl+C to stop"
echo " =================================================="
echo ""

# Run
if [ "$EUID" -eq 0 ]; then
    echo " [✅] Running as root — Live packet capture ENABLED"
else
    echo " [⚠️ ] Not root — Live capture disabled (dashboard still works)"
    echo " [⚠️ ] For live capture: sudo ./start_linux.sh"
fi
echo ""

# Run from project root so paths work correctly
$PYTHON backend/app.py
