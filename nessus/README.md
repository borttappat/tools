# nessus

Run Nessus Professional (Tenable's vendor Docker image) via a NixOS module or
a standalone Docker launcher. There's no nixpkgs package for Nessus and
packaging the proprietary binary natively isn't realistic, so this wraps
Tenable's own `tenable/nessus` image instead.

Tenable's Nessus image does not support external data volumes: the whole
container's writable layer has to survive restarts intact, or activation,
plugins, and scan results are lost. Keep that in mind however you deploy
this (`docker start`, not `docker rm` + fresh `docker run`, is what
`nessus-start` does after the first run).

## Standalone (any machine with Docker already running)

```bash
nix run "github:borttappat/tools?dir=nessus"
```

```bash
nix run "github:borttappat/tools?dir=nessus#nessus-stop"
```

Override defaults with env vars: `NESSUS_IMAGE`, `NESSUS_CONTAINER`,
`NESSUS_PORT`, `NESSUS_CREDENTIALS_DIR`.

## As a NixOS module

```nix
imports = [ (builtins.getFlake "github:borttappat/tools?dir=nessus").nixosModules.default ];
nessus.enable = true;
```

Requires `virtualisation.docker.enable = true;` in the same config.

Options: `image`, `containerName`, `port`, `credentialsDir`, `dataRoot`. See
`nessus.nix` for details.

- `dataRoot`: point this at a path on a disk that actually survives reboots
  on your system, and Docker's own storage gets redirected there
  (`virtualisation.docker.daemon.settings.data-root`), which is enough to
  keep the whole Nessus container intact across restarts. Left unset,
  Docker uses its default `/var/lib/docker`, and Nessus's state is only as
  persistent as that path is on your system.
- `credentialsDir`: a directory containing `activation_code`,
  `admin_username`, and `admin_password` files, however you deliver secrets
  onto this system. Without it, first `nessus-start` leaves activation to
  the web setup wizard at `https://<host>:8834` instead; with it, first boot
  activates non-interactively.

## Verified

Web setup wizard confirmed reachable at `https://localhost:8834` when run
inside a NixOS microVM with Docker enabled.
