# postman-drat development environment
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "postman-drat";

  buildInputs = with pkgs; [
    python3
    python3Packages.pip
    python3Packages.virtualenv

    # Document extraction
    pandoc
    poppler-utils

    # PST tools & build dependencies
    libpff
    gcc
    pkg-config
  ];

  shellHook = ''
    # Create and activate virtual environment
    VENV_DIR=".venv"
    if [ ! -d "$VENV_DIR" ]; then
      python3 -m venv "$VENV_DIR" 2>/dev/null
    fi
    source "$VENV_DIR/bin/activate" 2>/dev/null

    # Install Python dependencies from requirements.txt (skip if pypff already installed)
    if [ -f requirements.txt ] && ! python3 -c "import pypff" 2>/dev/null; then
      timeout 120 pip install -q --disable-pip-version-check --no-cache-dir -r requirements.txt 2>/dev/null &
      INSTALL_PID=$!
      wait $INSTALL_PID 2>/dev/null || true
    fi

    echo "postman-drat - Email & Document Extraction Toolkit"
    echo "===================================================="
    echo ""
    echo "Python: $(python3 --version)"
    echo "pandoc: $(pandoc --version | head -1)"
    echo "pdftotext: $(pdftotext -v 2>&1 | head -1)"
    echo ""
    echo "Tools available:"
    echo "  ./pst-export <mail.pst> [output_dir]   # Export a PST to emails/ + attachments/"
    echo "  ./exfil <file>                         # Extract text from a document"
    echo "  ./exfil -r <dir>                       # Recursive extraction"
    echo "  ./exfil -g \"pattern\" -r <dir>           # Grep across extracted content"
    echo ""
    echo "(Installing Python packages... first entry may take a moment)"
  '';
}
