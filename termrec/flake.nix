{
  description = "termrec - record every interactive terminal with asciinema, name sessions, read them back as text";

  # asciinema 3 (convert to text) needs a recent nixpkgs.
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    # Built from whichever nixpkgs the caller uses (the NixOS module passes the
    # system's own), so installing termrec adds no second nixpkgs to a closure.
    mkTermrec = pkgs:
      pkgs.stdenvNoCC.mkDerivation {
        pname = "termrec";
        version = "0.1.0";
        src = ./.;
        dontBuild = true;
        installPhase = ''
          share=$out/share/termrec
          mkdir -p $out/bin $share
          substitute termrec.sh $out/bin/termrec \
            --subst-var-by bash ${pkgs.bash}/bin/bash \
            --subst-var-by path ${pkgs.lib.makeBinPath [pkgs.asciinema pkgs.coreutils]} \
            --subst-var-by share $share
          chmod +x $out/bin/termrec
          for f in init.sh init.fish; do
            substitute init/$f $share/$f --subst-var-by termrec $out/bin/termrec
          done
        '';
        doInstallCheck = true;
        nativeInstallCheckInputs = [pkgs.shellcheck pkgs.fish];
        installCheckPhase = ''
          shellcheck -s bash $out/bin/termrec $out/share/termrec/init.sh
          fish --no-execute $out/share/termrec/init.fish
        '';
        meta = {
          description = "Record every interactive terminal with asciinema; name sessions, read them back as text";
          mainProgram = "termrec";
          platforms = pkgs.lib.platforms.linux;
        };
      };
  in
    flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux"] (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;

      shells = {
        bashInteractive = "${pkgs.bashInteractive}/bin/bash";
        zsh = "${pkgs.zsh}/bin/zsh";
        fish = "${pkgs.fish}/bin/fish";
      };

      termrec = mkTermrec pkgs;

      # Fills the shell and termrec paths into a helper script.
      withPaths = name: file: extra:
        pkgs.runCommand name {} ''
          mkdir -p $out/bin
          substitute ${file} $out/bin/${name} \
            --subst-var-by bash ${pkgs.bash}/bin/bash \
            --subst-var-by termrec ${termrec}/bin/termrec \
            --subst-var-by share ${termrec}/share/termrec \
            ${lib.concatStringsSep " " (lib.mapAttrsToList (k: v: "--subst-var-by ${k} ${v}") (shells // extra))}
          chmod +x $out/bin/${name}
        '';

      demo = withPaths "termrec-demo" ./demo.sh {};

      test = withPaths "termrec-test" ./tests/run.sh {
        path = lib.makeBinPath [pkgs.util-linux pkgs.coreutils pkgs.gnugrep pkgs.gawk];
      };
    in {
      packages = {
        default = termrec;
        inherit termrec demo test;
      };

      apps = {
        default = flake-utils.lib.mkApp {
          drv = demo;
          exePath = "/bin/termrec-demo";
        };
        termrec = flake-utils.lib.mkApp {drv = termrec;};
        test = flake-utils.lib.mkApp {
          drv = test;
          exePath = "/bin/termrec-test";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "termrec";
        packages = [termrec demo test pkgs.bashInteractive pkgs.zsh pkgs.fish];
        shellHook = ''
          echo ""
          echo "  termrec shell"
          echo "  run:  termrec-demo [bash|zsh|fish]   (recorded shell, temporary recordings)"
          echo "  run:  termrec-test [bash|zsh|fish]   (end-to-end test in real ptys)"
          echo "  run:  termrec --help"
          echo ""
        '';
      };

      # Real interactive sessions in ptys, as a terminal would run them.
      checks.default = pkgs.runCommand "termrec-test" {} ''
        export HOME=$TMPDIR
        ${test}/bin/termrec-test
        touch $out
      '';
    })
    // {
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.programs.termrec;
        init = file: lib.mkBefore "source ${cfg.package}/share/termrec/${file}";
      in {
        options.programs.termrec = {
          enable = lib.mkEnableOption "recording every interactive terminal with termrec";
          package = lib.mkOption {
            type = lib.types.package;
            default = mkTermrec pkgs;
            defaultText = lib.literalMD "termrec built from the system's nixpkgs (needs asciinema 3)";
            description = "The termrec package.";
          };
          dir = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "$HOME/engagement/logs";
            description = "Where recordings go (TERMREC_DIR). null keeps termrec's default, ~/terminal_logs.";
          };
          shells = lib.mkOption {
            type = lib.types.listOf (lib.types.enum ["bash" "zsh" "fish"]);
            default = ["bash" "zsh" "fish"];
            description = "Shells whose interactive sessions are recorded.";
          };
        };

        config = lib.mkIf cfg.enable {
          environment.systemPackages = [cfg.package];
          environment.variables = lib.optionalAttrs (cfg.dir != null) {TERMREC_DIR = cfg.dir;};
          programs.bash.interactiveShellInit = lib.mkIf (lib.elem "bash" cfg.shells) (init "init.sh");
          programs.zsh.interactiveShellInit = lib.mkIf (lib.elem "zsh" cfg.shells) (init "init.sh");
          programs.fish.interactiveShellInit = lib.mkIf (lib.elem "fish" cfg.shells) (init "init.fish");
        };
      };
    };
}
