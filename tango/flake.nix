{
  description = "Tango - File Share Reconnaissance and Analysis Tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        pythonEnv = pkgs.python3.withPackages (ps: with ps; [
          impacket
          python-magic
          colorama
          tika
          pyexiftool
        ]);

        runtimeTools = with pkgs; [
          jre        # Apache Tika
          exiftool   # embedded file metadata (EXIF/GPS, doc authorship, etc.)
          file       # libmagic backing python-magic
          binutils   # 'strings' for binary file analysis
          p7zip
          zip
          unzip
          samba      # SMB client, for manual testing against live shares
        ];

        tango = pkgs.stdenv.mkDerivation {
          pname = "tango";
          version = "1.1.0";
          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            mkdir -p $out/share/tango $out/bin
            cp *.py $out/share/tango/

            makeWrapper ${pythonEnv}/bin/python3 $out/bin/tango \
              --add-flags "$out/share/tango/tango.py" \
              --set JAVA_HOME "${pkgs.jre}" \
              --prefix PATH : "${pkgs.lib.makeBinPath runtimeTools}"
          '';

          meta.mainProgram = "tango";
        };
      in
      {
        packages.default = tango;
        apps.default = flake-utils.lib.mkApp { drv = tango; };

        devShells.default = pkgs.mkShell {
          name = "tango";

          buildInputs = [ pythonEnv ] ++ runtimeTools;

          shellHook = ''
            echo "Tango - File Share Reconnaissance Tool"
            echo "======================================="
            echo ""

            export JAVA_HOME="${pkgs.jre}"

            echo "Python: $(python3 --version)"
            echo "Java:   $(java -version 2>&1 | head -1)"
            echo "ExifTool: $(exiftool -ver)"
            echo ""
            echo "Usage:"
            echo "  python3 tango.py walk -t <IP> -u <user> -p <pass>     # SMB: index shares"
            echo "  python3 tango.py talk --filetypes txt,ini,pdf --metadata  # SMB: search + metadata"
            echo "  python3 tango.py local-walk /path/to/dump              # Local: index folder"
            echo "  python3 tango.py local-talk /path/to/dump --metadata   # Local: search + metadata"
            echo ""
            echo "Note: Tika will download its server JAR (~60MB) on first use."
            echo ""
          '';
        };
      });
}
