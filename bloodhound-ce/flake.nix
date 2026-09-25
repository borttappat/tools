{
  description = "BloodHound-CE (SpecterOps) - Docker launcher with graceful stop";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      # Same preflight as ../nessus: talk to the Docker socket directly when
      # the invoking user already has access (e.g. in the "docker" group);
      # fall back to sudo when they don't, rather than failing outright with
      # a permission error. Bare "sudo" (not ''${pkgs.sudo}/bin/sudo): NixOS's
      # usable sudo is the setuid wrapper at /run/wrappers/bin/sudo, found via
      # $PATH. The raw nixpkgs store binary is never setuid and always fails
      # with "must be owned by uid 0 and have the setuid bit set".
      # This flake ships the Docker *client* (pkgs.docker) so the wrapper
      # scripts always have something to invoke, but it does not install or
      # start a Docker *daemon* -- that has to already exist on the host.
      dockerCmd = ''
        DOCKER="${pkgs.docker}/bin/docker"
        if ! "$DOCKER" info >/dev/null 2>&1; then
          DOCKER="sudo $DOCKER"
        fi
        if ! $DOCKER info >/dev/null 2>&1; then
          echo "Error: could not reach a Docker daemon (tried directly and with sudo)." >&2
          echo "This tool needs Docker already installed and running on this machine." >&2
          echo "  systemd-based Linux: sudo systemctl start docker" >&2
          exit 1
        fi
      '';

      # Names prefixed bloodhound-ce- so nothing collides with other Docker
      # workloads on the same machine. Defaults and env var names match
      # upstream's own docker-compose.yml (SpecterOps/BloodHound
      # examples/docker-compose) so existing docs/tooling for BloodHound CE
      # still apply, except BLOODHOUND_TAG: pinned to a specific release
      # instead of upstream's floating "latest", so a background pull can't
      # change behavior mid-engagement (same rationale as ../nessus's image
      # pin). Containers share a user-defined bridge network and reach each
      # other by container name via Docker's embedded DNS, matching
      # upstream's own app-db/graph-db service-name addressing.
      env = ''
        NETWORK="bloodhound-ce"
        PG_VOLUME="bloodhound-ce-postgres-data"
        NEO4J_VOLUME="bloodhound-ce-neo4j-data"
        PG_CONTAINER="bloodhound-ce-app-db"
        NEO4J_CONTAINER="bloodhound-ce-graph-db"
        BH_CONTAINER="bloodhound-ce-bloodhound"

        POSTGRES_USER="''${POSTGRES_USER:-bloodhound}"
        POSTGRES_PASSWORD="''${POSTGRES_PASSWORD:-bloodhoundcommunityedition}"
        POSTGRES_DB="''${POSTGRES_DB:-bloodhound}"
        NEO4J_USER="''${NEO4J_USER:-neo4j}"
        NEO4J_SECRET="''${NEO4J_SECRET:-bloodhoundcommunityedition}"
        BLOODHOUND_TAG="''${BLOODHOUND_TAG:-9.7.1}"
        BLOODHOUND_PORT="''${BLOODHOUND_PORT:-8080}"
        NEO4J_WEB_PORT="''${NEO4J_WEB_PORT:-7474}"
        NEO4J_DB_PORT="''${NEO4J_DB_PORT:-7687}"
        bhe_disable_cypher_complexity_limit="''${bhe_disable_cypher_complexity_limit:-false}"
        bhe_enable_cypher_mutations="''${bhe_enable_cypher_mutations:-false}"
        bhe_graph_query_memory_limit="''${bhe_graph_query_memory_limit:-2}"
        bhe_recreate_default_admin="''${bhe_recreate_default_admin:-false}"
      '';

      ensureNetwork = ''
        if ! $DOCKER network inspect "$NETWORK" >/dev/null 2>&1; then
          echo "Creating network $NETWORK..."
          $DOCKER network create "$NETWORK" >/dev/null
        fi
      '';

      startStack = ''
        if $DOCKER inspect "$PG_CONTAINER" >/dev/null 2>&1; then
          $DOCKER start "$PG_CONTAINER" >/dev/null
        else
          echo "Creating Postgres container (first run)..."
          $DOCKER run -d --network "$NETWORK" --name "$PG_CONTAINER" \
            -e PGUSER="$POSTGRES_USER" \
            -e POSTGRES_USER="$POSTGRES_USER" \
            -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
            -e POSTGRES_DB="$POSTGRES_DB" \
            -v "$PG_VOLUME:/var/lib/postgresql" \
            --health-cmd "pg_isready -U $POSTGRES_USER -d $POSTGRES_DB -h 127.0.0.1 -p 5432" \
            --health-interval=10s --health-timeout=5s --health-retries=5 --health-start-period=30s \
            docker.io/library/postgres:18 >/dev/null
        fi

        if $DOCKER inspect "$NEO4J_CONTAINER" >/dev/null 2>&1; then
          $DOCKER start "$NEO4J_CONTAINER" >/dev/null
        else
          echo "Creating Neo4j container (first run)..."
          $DOCKER run -d --network "$NETWORK" --name "$NEO4J_CONTAINER" \
            -e NEO4J_AUTH="$NEO4J_USER/$NEO4J_SECRET" \
            -e NEO4J_dbms_allow__upgrade=true \
            -v "$NEO4J_VOLUME:/data" \
            -p "127.0.0.1:$NEO4J_WEB_PORT:7474" \
            -p "127.0.0.1:$NEO4J_DB_PORT:7687" \
            --health-cmd "wget -O /dev/null -q http://localhost:7474 || exit 1" \
            --health-interval=10s --health-timeout=5s --health-retries=5 --health-start-period=30s \
            docker.io/library/neo4j:4.4.42 >/dev/null
        fi

        echo "Waiting for Postgres and Neo4j to become healthy..."
        for name in "$PG_CONTAINER" "$NEO4J_CONTAINER"; do
          healthy=""
          for i in $(seq 1 60); do
            status=$($DOCKER inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null || echo starting)
            if [ "$status" = "healthy" ]; then
              healthy=1
              break
            fi
            sleep 2
          done
          if [ -z "$healthy" ]; then
            echo "Error: $name did not become healthy in time. Check: docker logs $name" >&2
            exit 1
          fi
        done

        if $DOCKER inspect "$BH_CONTAINER" >/dev/null 2>&1; then
          $DOCKER start "$BH_CONTAINER" >/dev/null
        else
          echo "Creating BloodHound container (first run)..."
          $DOCKER run -d --network "$NETWORK" --name "$BH_CONTAINER" \
            -e bhe_disable_cypher_complexity_limit="$bhe_disable_cypher_complexity_limit" \
            -e bhe_enable_cypher_mutations="$bhe_enable_cypher_mutations" \
            -e bhe_graph_query_memory_limit="$bhe_graph_query_memory_limit" \
            -e bhe_database_connection="user=$POSTGRES_USER password=$POSTGRES_PASSWORD dbname=$POSTGRES_DB host=$PG_CONTAINER" \
            -e bhe_neo4j_connection="neo4j://$NEO4J_USER:$NEO4J_SECRET@$NEO4J_CONTAINER:7687/" \
            -e bhe_recreate_default_admin="$bhe_recreate_default_admin" \
            -e bhe_graph_driver="neo4j" \
            -p "127.0.0.1:$BLOODHOUND_PORT:8080" \
            "docker.io/specterops/bloodhound:$BLOODHOUND_TAG" >/dev/null
        fi

        echo "BloodHound CE: http://127.0.0.1:$BLOODHOUND_PORT/ui/login"
      '';

      # The admin password is only ever printed once, in the BloodHound
      # container's own boxed log message, on the boot that first creates
      # the account. "docker logs" replays the full retained history of a
      # container (not just new output), so this still finds it on a restart
      # of an existing container -- only a wipe + fresh container regenerates
      # it. Swallow a no-match grep (exit 1) each attempt; only give up
      # after the retry budget.
      waitForPassword = ''
        echo "Waiting for the initial admin password (only printed once, on first boot)..."
        PASSWORD_BOX=""
        for i in $(seq 1 60); do
          PASSWORD_BOX=$($DOCKER logs "$BH_CONTAINER" 2>&1 | grep -B2 -A2 -m1 "Initial Password Set To" || true)
          [ -n "$PASSWORD_BOX" ] && break
          sleep 2
        done
      '';

      bloodhoundStart = pkgs.writeShellScriptBin "bloodhound-start" ''
        set -e
        ${dockerCmd}
        ${env}
        ${ensureNetwork}
        ${startStack}
        ${waitForPassword}

        printf '\033[2J\033[H'
        echo "BloodHound CE: http://127.0.0.1:$BLOODHOUND_PORT/ui/login"
        echo ""
        if [ -n "$PASSWORD_BOX" ]; then
          echo "$PASSWORD_BOX"
        else
          echo "Admin password not found in logs (already created earlier, or check: docker logs $BH_CONTAINER)"
        fi
        echo ""
        echo "Data is preserved across stops. Full reset: nix run \"github:borttappat/tools?dir=bloodhound-ce#bloodhound-wipe\""
        echo "Press Ctrl+C to stop."

        while true; do
          stop_requested=""
          trap 'stop_requested=1' INT TERM
          while [ -z "$stop_requested" ]; do
            sleep 1 || true
          done
          trap - INT TERM
          printf "\nStop BloodHound CE? Containers stop, data is preserved. [y/N] "
          read -r reply < /dev/tty || true
          case "$reply" in
            y | Y) break ;;
            *) echo "Resuming. Press Ctrl+C to stop." ;;
          esac
        done

        echo "Stopping BloodHound CE..."
        $DOCKER stop "$PG_CONTAINER" "$NEO4J_CONTAINER" "$BH_CONTAINER" >/dev/null
        echo "Stopped. Data preserved; start again: nix run \"github:borttappat/tools?dir=bloodhound-ce\""
      '';

      bloodhoundDetach = pkgs.writeShellScriptBin "bloodhound-detach" ''
        set -e
        ${dockerCmd}
        ${env}
        ${ensureNetwork}
        ${startStack}
        ${waitForPassword}

        echo ""
        if [ -n "$PASSWORD_BOX" ]; then
          echo "$PASSWORD_BOX"
        else
          echo "Admin password not found in logs (already created earlier, or check: docker logs $BH_CONTAINER)"
        fi
        echo ""
        echo "Running in the background."
        echo "Stop: nix run \"github:borttappat/tools?dir=bloodhound-ce#bloodhound-stop\""
      '';

      bloodhoundStop = pkgs.writeShellScriptBin "bloodhound-stop" ''
        set -e
        ${dockerCmd}
        ${env}
        echo "Stopping BloodHound CE..."
        $DOCKER stop "$PG_CONTAINER" "$NEO4J_CONTAINER" "$BH_CONTAINER" >/dev/null
        echo "Stopped (data preserved). Start again: nix run \"github:borttappat/tools?dir=bloodhound-ce\""
      '';

      bloodhoundWipe = pkgs.writeShellScriptBin "bloodhound-wipe" ''
        set -e
        ${dockerCmd}
        ${env}

        if [ "''${BLOODHOUND_WIPE_CONFIRM:-}" != "1" ]; then
          echo "This will permanently delete the BloodHound CE containers and all Postgres/Neo4j data (collected AD data, users, sessions)."
          printf "Type 'yes' to continue: "
          read -r reply
          if [ "$reply" != "yes" ]; then
            echo "Aborted."
            exit 1
          fi
        fi

        echo "Removing containers, network, and volumes..."
        $DOCKER rm -f "$PG_CONTAINER" "$NEO4J_CONTAINER" "$BH_CONTAINER" >/dev/null 2>&1 || true
        $DOCKER network rm "$NETWORK" >/dev/null 2>&1 || true
        $DOCKER volume rm "$PG_VOLUME" "$NEO4J_VOLUME" >/dev/null 2>&1 || true
        echo "BloodHound CE fully wiped."
      '';
    in {
      packages.default = bloodhoundStart;

      apps = {
        default = flake-utils.lib.mkApp {
          drv = bloodhoundStart;
          exePath = "/bin/bloodhound-start";
        };
        bloodhound-start = flake-utils.lib.mkApp {
          drv = bloodhoundStart;
          exePath = "/bin/bloodhound-start";
        };
        bloodhound-detach = flake-utils.lib.mkApp {
          drv = bloodhoundDetach;
          exePath = "/bin/bloodhound-detach";
        };
        bloodhound-stop = flake-utils.lib.mkApp {
          drv = bloodhoundStop;
          exePath = "/bin/bloodhound-stop";
        };
        bloodhound-wipe = flake-utils.lib.mkApp {
          drv = bloodhoundWipe;
          exePath = "/bin/bloodhound-wipe";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "bloodhound-ce";

        buildInputs = [pkgs.docker bloodhoundStart bloodhoundDetach bloodhoundStop bloodhoundWipe];

        shellHook = ''
          echo "BloodHound CE - Docker launcher"
          echo "================================"
          echo ""
          echo "Requires a running Docker daemon (systemctl start docker)."
          echo ""
          echo "  bloodhound-start    # create/start everything, attach to logs, Ctrl+C to stop"
          echo "  bloodhound-detach   # same, but returns immediately (runs in background)"
          echo "  bloodhound-stop     # stop a detached run (data preserved)"
          echo "  bloodhound-wipe     # stop and permanently delete all data"
          echo ""
          echo "Override with env vars: POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB,"
          echo "NEO4J_USER, NEO4J_SECRET, BLOODHOUND_TAG, BLOODHOUND_PORT, NEO4J_WEB_PORT,"
          echo "NEO4J_DB_PORT, bhe_disable_cypher_complexity_limit, bhe_enable_cypher_mutations,"
          echo "bhe_graph_query_memory_limit, bhe_recreate_default_admin"
          echo ""
        '';
      };
    });
}
