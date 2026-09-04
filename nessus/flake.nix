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
      # Bare "sudo" (not ''${pkgs.sudo}/bin/sudo): NixOS's usable sudo is the
      # setuid wrapper at /run/wrappers/bin/sudo, found via $PATH. The raw
      # nixpkgs store binary is never setuid and always fails with "must be
      # owned by uid 0 and have the setuid bit set".
      # This flake ships the Docker *client* (pkgs.docker) so the wrapper
      # scripts always have something to invoke, but it does not install or
      # start a Docker *daemon* -- that has to already exist on the host
      # (Docker Engine, Docker Desktop, or a compatible socket such as
      # rootless Podman). dockerCmd resolves DOCKER to a working invocation
      # (plain, or sudo-prefixed for a socket the caller can't reach
      # directly), and exits with a clear message up front if neither
      # reaches a live daemon at all, instead of letting a later `docker
      # run` fail with a raw connection-refused error.
      dockerCmd = ''
        DOCKER="${pkgs.docker}/bin/docker"
        if ! "$DOCKER" info >/dev/null 2>&1; then
          DOCKER="sudo $DOCKER"
        fi
        if ! $DOCKER info >/dev/null 2>&1; then
          echo "Error: could not reach a Docker daemon (tried directly and with sudo)." >&2
          echo "This tool needs Docker (or a compatible daemon, e.g. rootless Podman exposing a docker socket) already installed and running on this machine." >&2
          echo "  systemd-based Linux: sudo systemctl start docker" >&2
          exit 1
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
          $DOCKER start "$NESSUS_CONTAINER" >/dev/null
        else
          echo "Creating Nessus container (first run)..."
          if [ -n "''${NESSUS_CREDENTIALS_DIR:-}" ]; then
            $DOCKER run -d \
              --name "$NESSUS_CONTAINER" \
              -p "$NESSUS_PORT:8834" \
              -e ACTIVATION_CODE="$(cat "$NESSUS_CREDENTIALS_DIR/activation_code")" \
              -e USERNAME="$(cat "$NESSUS_CREDENTIALS_DIR/admin_username")" \
              -e PASSWORD="$(cat "$NESSUS_CREDENTIALS_DIR/admin_password")" \
              "$NESSUS_IMAGE" >/dev/null
          else
            $DOCKER run -d \
              --name "$NESSUS_CONTAINER" \
              -p "$NESSUS_PORT:8834" \
              "$NESSUS_IMAGE" >/dev/null
          fi
        fi

        echo "Nessus: https://localhost:$NESSUS_PORT"
        echo "To stop: nix run \"github:borttappat/tools?dir=nessus#nessus-stop\""
      '';

      nessusStop = pkgs.writeShellScriptBin "nessus-stop" ''
        set -e
        ${dockerCmd}
        NESSUS_CONTAINER="''${NESSUS_CONTAINER:-nessus}"
        echo "Stopping Nessus..."
        $DOCKER stop "$NESSUS_CONTAINER" >/dev/null
        echo "Nessus stopped. To start it again: nix run \"github:borttappat/tools?dir=nessus\""
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
