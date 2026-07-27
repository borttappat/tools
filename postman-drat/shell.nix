# postman-drat development environment
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "postman-drat";

  buildInputs = with pkgs; [
    python3
    python3Packages.pip
    python3Packages.venvShellHook

    # pffexport CLI + headers (needed to build the libpff-python bindings below)
    libpff

    # Document extraction
    pandoc
    poppler-utils

    # Build toolchain for compiling libpff-python against libpff
    gcc
    pkg-config
  ];

  venvDir = "./venv";

  postShellHook = ''
    pip install --quiet -r requirements.txt
  '';

  shellHook = ''
    echo "postman-drat - Email & Document Extraction Toolkit"
    echo "===================================================="
    echo ""
    echo "Python: $(python3 --version)"
    echo "pandoc: $(pandoc --version | head -1)"
    echo "pdftotext: $(pdftotext -v 2>&1 | head -1)"
    echo ""
    echo "Usage:"
    echo "  ./pst-export <mail.pst> [output_dir]   # Export a PST to emails/ + attachments/"
    echo "  ./exfil <file>                         # Extract text from a document"
    echo "  ./exfil -r <dir>                       # Recursive extraction"
    echo "  ./exfil -g \"pattern\" -r <dir>           # Grep across extracted content"
    echo ""
  '';
}
