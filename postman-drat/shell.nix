# postman-drat development environment
{ pkgs ? import <nixpkgs> {} }:

let
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    openpyxl
    python-pptx
    python-docx
  ]);

in

pkgs.mkShell {
  name = "postman-drat";

  buildInputs = with pkgs; [
    pythonEnv

    # Document extraction
    pandoc
    poppler_utils

    # PST tools (pffexport / pffinfo)
    libpff
  ];

  shellHook = ''
    echo "postman-drat - Email & Document Extraction Toolkit"
    echo "===================================================="
    echo ""
    echo "Python: $(python3 --version)"
    echo "pandoc: $(pandoc --version | head -1)"
    echo "pdftotext: $(pdftotext -v 2>&1 | head -1)"
    echo "pffexport: $(pffexport -V 2>&1 | head -1)"
    echo ""
    echo "Tools available:"
    echo "  ./pst-export <mail.pst> [output_dir]   # Export a PST to emails/ + attachments/"
    echo "  ./exfil <file>                         # Extract text from a document"
    echo "  ./exfil -r <dir>                       # Recursive extraction"
    echo "  ./exfil -g \"pattern\" -r <dir>           # Grep across extracted content"
    echo ""
  '';
}
