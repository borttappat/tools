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
    export VENV_DIR=".venv"
    if [ ! -d "$VENV_DIR" ]; then
      python3 -m venv "$VENV_DIR"
    fi
    source "$VENV_DIR/bin/activate"

    # Install Python dependencies from requirements.txt
    # Use the venv's pip, not the system pip
    if [ -f requirements.txt ]; then
      pip install --quiet -r requirements.txt
    fi

    echo "postman-drat - Email & Document Extraction Toolkit"
    echo "===================================================="
    echo ""
    echo "Python: $(python --version)"
    echo "pandoc: $(pandoc --version | head -1)"
    echo "pdftotext: $(pdftotext -v 2>&1 | head -1)"
    echo ""
    echo "Tools available:"
    echo "  ./pst-export <mail.pst> [output_dir]   # Export a PST to emails/ + attachments/"
    echo "  ./exfil <file>                         # Extract text from a document"
    echo "  ./exfil -r <dir>                       # Recursive extraction"
    echo "  ./exfil -g \"pattern\" -r <dir>           # Grep across extracted content"
    echo ""
  '';
}
