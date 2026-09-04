{
  description = "Nessus Professional (Tenable) - NixOS module + standalone Docker launcher";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    {
      nixosModules.default = import ./nessus.nix;
      nixosModules.nessus = import ./nessus.nix;
    }
    // flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      # Standalone equivalent of the module's nessus-start, for a machine
      # that already has a Docker daemon running but doesn't want to wire
      # in the NixOS module. Same defaults, overridable via env vars.
      # Talk to the Docker socket directly when the invoking user already
      # has access (e.g. in the "docker" group); fall back to sudo when
      # they don't, rather than failing outright with a permission error.
      dockerCmd = ''
        DOCKER="${pkgs.docker}/bin/docker"
        if ! "$DOCKER" info >/dev/null 2>&1; then
          DOCKER="${pkgs.sudo}/bin/sudo $DOCKER"
        fi
      '';

      nessusStart = pkgs.writeShellScriptBin "nessus-start" ''
        set -e

        ${dockerCmd}

        NESSUS_IMAGE="''${NESSUS_IMAGE:-tenable/nessus:10.12.4-ubuntu}"
        NESSUS_CONTAINER="''${NESSUS_CONTAINER:-nessus}"
        NESSUS_PORT="''${NESSUS_PORT:-8834}"

        if $DOCKER inspect "$NESSUS_CONTAINER" >/dev/null 2>&1; then
          echo "Starting existing Nessus container..."
          $DOCKER start "$NESSUS_CONTAINER"
        else
          echo "Creating Nessus container (first run)..."
          if [ -n "''${NESSUS_CREDENTIALS_DIR:-}" ]; then
            $DOCKER run -d \
              --name "$NESSUS_CONTAINER" \
              -p "$NESSUS_PORT:8834" \
              -e ACTIVATION_CODE="$(cat "$NESSUS_CREDENTIALS_DIR/activation_code")" \
              -e USERNAME="$(cat "$NESSUS_CREDENTIALS_DIR/admin_username")" \
              -e PASSWORD="$(cat "$NESSUS_CREDENTIALS_DIR/admin_password")" \
              "$NESSUS_IMAGE"
          else
            $DOCKER run -d \
              --name "$NESSUS_CONTAINER" \
              -p "$NESSUS_PORT:8834" \
              "$NESSUS_IMAGE"
          fi
        fi

        echo "Nessus: https://localhost:$NESSUS_PORT"
      '';

      nessusStop = pkgs.writeShellScriptBin "nessus-stop" ''
        set -e
        ${dockerCmd}
        NESSUS_CONTAINER="''${NESSUS_CONTAINER:-nessus}"
        $DOCKER stop "$NESSUS_CONTAINER"
      '';
    in {
      packages.default = nessusStart;

      apps = {
        default = flake-utils.lib.mkApp {
          drv = nessusStart;
          exePath = "/bin/nessus-start";
        };
        nessus-start = flake-utils.lib.mkApp {
          drv = nessusStart;
          exePath = "/bin/nessus-start";
        };
        nessus-stop = flake-utils.lib.mkApp {
          drv = nessusStop;
          exePath = "/bin/nessus-stop";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "nessus";

        buildInputs = [pkgs.docker nessusStart nessusStop];

        shellHook = ''
          echo "Nessus Professional - Docker launcher"
          echo "======================================"
          echo ""
          echo "Requires a running Docker daemon (systemctl start docker, or rootless podman/docker)."
          echo ""
          echo "  nessus-start   # create/start the container, prints the URL"
          echo "  nessus-stop    # stop it"
          echo ""
          echo "Override with env vars: NESSUS_IMAGE, NESSUS_CONTAINER, NESSUS_PORT, NESSUS_CREDENTIALS_DIR"
          echo ""
          echo "For a NixOS system, prefer importing the module instead of this shell:"
          echo "  imports = [ (builtins.getFlake \"github:borttappat/tools?dir=nessus\").nixosModules.default ];"
          echo "  nessus.enable = true;"
          echo ""
        '';
      };
    });
}
