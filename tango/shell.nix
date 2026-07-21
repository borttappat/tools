# Tango development environment
{ pkgs ? import <nixpkgs> {} }:

let
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    pip
    setuptools
    wheel
    virtualenv
  ]);

in

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Python
    pythonEnv

    # Java runtime - required by Apache Tika
    jre

    # libmagic - required by python-magic
    file

    # 'strings' command - for binary file analysis
    binutils

    # Archive tools
    p7zip
    zip
    unzip

    # SMB client (for manual testing against live shares)
    samba
  ];

  shellHook = ''
    echo "Tango - File Share Reconnaissance Tool"
    echo "======================================="
    echo ""

    # libmagic path for python-magic
    export LD_LIBRARY_PATH="${pkgs.file}/lib:$LD_LIBRARY_PATH"

    # Java for Apache Tika
    export JAVA_HOME="${pkgs.jre}"

    # Create venv if it doesn't exist
    if [ ! -d "venv" ]; then
      python3 -m venv venv
      echo "Virtual environment created"
    fi

    source venv/bin/activate

    # Install/update dependencies
    if [ -f "requirements.txt" ]; then
      if ! pip install --quiet -r requirements.txt; then
        echo ""
        echo "WARNING: pip install failed - dependencies may be missing or outdated."
        echo "         Check network/PyPI access (e.g. air-gapped machine) and re-run:"
        echo "         pip install -r requirements.txt"
        echo ""
      fi
    fi

    echo "Python: $(python3 --version)"
    echo "Java:   $(java -version 2>&1 | head -1)"
    echo ""
    echo "Usage:"
    echo "  python3 tango.py walk -t <IP> -u <user> -p <pass>     # SMB: index shares"
    echo "  python3 tango.py talk --filetypes txt,ini,pdf,docx     # SMB: search files"
    echo "  python3 tango.py local-walk /path/to/dump              # Local: index folder"
    echo "  python3 tango.py local-talk /path/to/dump              # Local: search folder"
    echo ""
    echo "Note: Tika will download its server JAR (~60MB) on first use."
    echo ""
  '';
}
