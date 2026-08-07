{
  description = "postman-drat - Email & Document Extraction Toolkit";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        pythonEnv = pkgs.python3.withPackages (ps: with ps; [
          openpyxl
          python-pptx
          python-docx
        ]);

        runtimeTools = [
          pythonEnv
          pkgs.pandoc
          pkgs.poppler_utils
          pkgs.libpff  # pffexport / pffinfo
        ];

        postmanDrat = pkgs.stdenv.mkDerivation {
          pname = "postman-drat";
          version = "1.0.0";
          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            mkdir -p $out/bin
            install -m755 pst-export $out/bin/pst-export
            install -m755 exfil $out/bin/exfil

            wrapProgram $out/bin/pst-export \
              --prefix PATH : "${pkgs.lib.makeBinPath runtimeTools}"

            wrapProgram $out/bin/exfil \
              --prefix PATH : "${pkgs.lib.makeBinPath runtimeTools}:$out/bin"
          '';

          meta.mainProgram = "exfil";
        };
      in
      {
        packages.default = postmanDrat;

        apps = {
          default = flake-utils.lib.mkApp { drv = postmanDrat; exePath = "/bin/exfil"; };
          exfil = flake-utils.lib.mkApp { drv = postmanDrat; exePath = "/bin/exfil"; };
          pst-export = flake-utils.lib.mkApp { drv = postmanDrat; exePath = "/bin/pst-export"; };
        };

        devShells.default = pkgs.mkShell {
          name = "postman-drat";

          buildInputs = runtimeTools;

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
        };
      });
}
