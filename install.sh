#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/mobadawyx4/SubReconX.git"
INSTALL_DIR="${SUBRECONX_HOME:-$HOME/.local/share/subreconx}"
BIN_DIR="${SUBRECONX_BIN:-$HOME/.local/bin}"
VENV="$INSTALL_DIR/.venv"

echo "[SubReconX] Checking prerequisites..."

if ! command -v git >/dev/null 2>&1; then
    echo "Error: Git is required. Install Git and retry."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required."
    exit 1
fi

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
    echo "Error: Python 3.10 or newer is required."
    exit 1
}

mkdir -p "$(dirname "$INSTALL_DIR")" "$BIN_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[SubReconX] Updating existing installation..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    if [ -e "$INSTALL_DIR" ]; then
        echo "Error: $INSTALL_DIR exists but is not a Git repository."
        exit 1
    fi
    echo "[SubReconX] Downloading source..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR"
fi

if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi

echo "[SubReconX] Installing..."
"$VENV/bin/python" -m pip install --no-deps "$INSTALL_DIR"

cat > "$BIN_DIR/subreconx" <<LAUNCHER
#!/usr/bin/env bash
exec "$VENV/bin/subreconx" "\$@"
LAUNCHER

chmod +x "$BIN_DIR/subreconx"

echo
echo "SubReconX installed successfully."
echo "Run: $BIN_DIR/subreconx --help"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo
        echo "Add this directory to your PATH:"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
        echo "Add that line to ~/.bashrc or ~/.zshrc."
        ;;
esac
