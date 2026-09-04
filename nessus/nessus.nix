# Nessus Professional (Tenable), run via their official Docker image.
#
# Import as a NixOS module and enable:
#
#   imports = [ ./nessus.nix ];
#   nessus.enable = true;
#
# Tenable's Nessus image does not support external data volumes: the whole
# container's writable layer has to survive restarts intact, or activation,
# plugins, and scan results are lost. This module does not manage
# persistence itself, but if you point nessus.dataRoot at a path on a disk
# that survives reboots, it redirects Docker's own storage there
# (virtualisation.docker.daemon.settings.data-root), which is enough to keep
# the whole container intact across restarts.
#
# Precondition this module does not set up itself:
#   virtualisation.docker.enable = true; somewhere in the importing config.
#
# Optional non-interactive first boot:
#   nessus.credentialsDir = "/some/decrypted/secrets/dir";
# pointing at a directory with activation_code, admin_username, and
# admin_password files, however you get secrets onto this system (sops-nix,
# agenix, a mounted volume, ...). Without it, nessus-start still works;
# complete activation once through the web setup wizard at
# https://<host>:8834 instead.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.nessus;
in {
  options.nessus = {
    enable = lib.mkEnableOption "Nessus Professional (Docker)";

    image = lib.mkOption {
      type = lib.types.str;
      default = "tenable/nessus:10.12.4-ubuntu";
      description = "tenable/nessus image tag. Pin an explicit version (not latest-*) so a background docker pull cannot change scanner behavior mid-engagement.";
    };

    containerName = lib.mkOption {
      type = lib.types.str;
      default = "nessus";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8834;
    };

    credentialsDir = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Directory with activation_code, admin_username, and admin_password files, for non-interactive first boot. See module header.";
    };

    dataRoot = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "If set, points Docker's own storage (virtualisation.docker.daemon.settings.data-root) at this path, so the Nessus container's writable layer survives reboots. Point it at a mount on this system that actually persists.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [
        (pkgs.writeShellScriptBin "nessus-start" ''
          set -e

          ${pkgs.sudo}/bin/sudo ${pkgs.systemd}/bin/systemctl start docker

          if ${pkgs.docker}/bin/docker inspect ${cfg.containerName} >/dev/null 2>&1; then
            echo "Starting existing Nessus container..."
            ${pkgs.sudo}/bin/sudo ${pkgs.docker}/bin/docker start ${cfg.containerName}
          else
            echo "Creating Nessus container (first run)..."
            ${
            if cfg.credentialsDir != null
            then ''
              ${pkgs.sudo}/bin/sudo ${pkgs.docker}/bin/docker run -d \
                --name ${cfg.containerName} \
                -p ${toString cfg.port}:8834 \
                -e ACTIVATION_CODE="$(cat ${cfg.credentialsDir}/activation_code)" \
                -e USERNAME="$(cat ${cfg.credentialsDir}/admin_username)" \
                -e PASSWORD="$(cat ${cfg.credentialsDir}/admin_password)" \
                ${cfg.image}
            ''
            else ''
              ${pkgs.sudo}/bin/sudo ${pkgs.docker}/bin/docker run -d \
                --name ${cfg.containerName} \
                -p ${toString cfg.port}:8834 \
                ${cfg.image}
            ''
          }
          fi

          echo "Nessus: https://localhost:${toString cfg.port}"
        '')

        (pkgs.writeShellScriptBin "nessus-stop" ''
          ${pkgs.sudo}/bin/sudo ${pkgs.docker}/bin/docker stop ${cfg.containerName}
        '')

        (pkgs.writeShellScriptBin "nessus-status" ''
          ${pkgs.docker}/bin/docker ps --filter name=${cfg.containerName}
        '')
      ];
    }

    (lib.mkIf (cfg.dataRoot != null) {
      virtualisation.docker.daemon.settings.data-root = cfg.dataRoot;
    })
  ]);
}
