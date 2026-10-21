{
  description = "cashe - record every interactive terminal with asciinema, name sessions, read them back as text";

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
    # system's own), so installing cashe adds no second nixpkgs to a closure.
    mkCashe = pkgs:
      pkgs.stdenvNoCC.mkDerivation {
        pname = "cashe";
        version = "0.1.0";
        src = ./.;
        dontBuild = true;
        installPhase = ''
          share=$out/share/cashe
          mkdir -p $out/bin $share
          substitute cashe.sh $out/bin/cashe \
            --subst-var-by bash ${pkgs.bash}/bin/bash \
            --subst-var-by path ${pkgs.lib.makeBinPath [pkgs.asciinema pkgs.coreutils]} \
            --subst-var-by share $share
          chmod +x $out/bin/cashe
          for f in init.sh init.fish; do
            substitute init/$f $share/$f --subst-var-by cashe $out/bin/cashe
          done
        '';
        doInstallCheck = true;
        nativeInstallCheckInputs = [pkgs.shellcheck pkgs.fish];
        installCheckPhase = ''
          shellcheck -s bash $out/bin/cashe $out/share/cashe/init.sh
          fish --no-execute $out/share/cashe/init.fish
        '';
        meta = {
          description = "Record every interactive terminal with asciinema; name sessions, read them back as text";
          mainProgram = "cashe";
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

      cashe = mkCashe pkgs;

      # Fills the shell and cashe paths into a helper script.
      withPaths = name: file: extra:
        pkgs.runCommand name {} ''
          mkdir -p $out/bin
          substitute ${file} $out/bin/${name} \
            --subst-var-by bash ${pkgs.bash}/bin/bash \
            --subst-var-by cashe ${cashe}/bin/cashe \
            --subst-var-by share ${cashe}/share/cashe \
            ${lib.concatStringsSep " " (lib.mapAttrsToList (k: v: "--subst-var-by ${k} ${v}") (shells // extra))}
          chmod +x $out/bin/${name}
        '';

      demo = withPaths "cashe-demo" ./demo.sh {};

      test = withPaths "cashe-test" ./tests/run.sh {
        path = lib.makeBinPath [pkgs.util-linux pkgs.coreutils pkgs.gnugrep pkgs.gawk];
      };
    in {
      packages = {
        default = cashe;
        inherit cashe demo test;
      };

      apps = {
        default = flake-utils.lib.mkApp {
          drv = demo;
          exePath = "/bin/cashe-demo";
        };
        cashe = flake-utils.lib.mkApp {drv = cashe;};
        test = flake-utils.lib.mkApp {
          drv = test;
          exePath = "/bin/cashe-test";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "cashe";
        packages = [cashe demo test pkgs.bashInteractive pkgs.zsh pkgs.fish];
        shellHook = ''
          echo ""
          echo "  cashe shell"
          echo "  run:  cashe-demo [bash|zsh|fish]   (recorded shell, temporary recordings)"
          echo "  run:  cashe-test [bash|zsh|fish]   (end-to-end test in real ptys)"
          echo "  run:  cashe --help"
          echo ""
        '';
      };

      # Real interactive sessions in ptys, as a terminal would run them.
      checks.default = pkgs.runCommand "cashe-test" {} ''
        export HOME=$TMPDIR
        ${test}/bin/cashe-test
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
        cfg = config.programs.cashe;
        init = file: lib.mkBefore "source ${cfg.package}/share/cashe/${file}";
      in {
        options.programs.cashe = {
          enable = lib.mkEnableOption "recording every interactive terminal with cashe";
          package = lib.mkOption {
            type = lib.types.package;
            default = mkCashe pkgs;
            defaultText = lib.literalMD "cashe built from the system's nixpkgs (needs asciinema 3)";
            description = "The cashe package.";
          };
          dir = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "$HOME/engagement/logs";
            description = "Where recordings go (CASHE_DIR). null keeps cashe's default, ~/terminal_logs.";
          };
          shells = lib.mkOption {
            type = lib.types.listOf (lib.types.enum ["bash" "zsh" "fish"]);
            default = ["bash" "zsh" "fish"];
            description = "Shells whose interactive sessions are recorded.";
          };
        };

        config = lib.mkIf cfg.enable {
          environment.systemPackages = [cfg.package];
          environment.variables = lib.optionalAttrs (cfg.dir != null) {CASHE_DIR = cfg.dir;};
          programs.bash.interactiveShellInit = lib.mkIf (lib.elem "bash" cfg.shells) (init "init.sh");
          programs.zsh.interactiveShellInit = lib.mkIf (lib.elem "zsh" cfg.shells) (init "init.sh");
          programs.fish.interactiveShellInit = lib.mkIf (lib.elem "fish" cfg.shells) (init "init.fish");
        };
      };
    };
}
