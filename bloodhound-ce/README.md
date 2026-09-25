# bloodhound-ce

Run BloodHound CE (SpecterOps' AD/Entra attack-path analysis tool) via
Docker. This wraps the same three services upstream's own
`docker-compose.yml` defines (Postgres, Neo4j, the BloodHound API/UI) as
plain `docker run` invocations on a user-defined bridge network, same
approach as `../nessus`: no compose file, no dependency on a compose plugin
being installed.

Requires Docker already installed and running on this machine (Docker
Engine or Docker Desktop). This flake ships the Docker *client* so the
commands below always have something to invoke, but it does not install or
start a Docker *daemon* -- that has to already be running
(`sudo systemctl start docker` on a systemd-based Linux system). If your
user can already talk to the Docker socket directly (e.g. in the `docker`
group), it runs unprivileged; otherwise it falls back to `sudo`
automatically and may prompt for a password. If no daemon is reachable
either way, it exits early with a clear error.

## Standalone

```bash
nix run "github:borttappat/tools?dir=bloodhound-ce"
```

This creates the network and all three containers on first run (subsequent
runs just restart them), waits for Postgres and Neo4j to report healthy,
then attaches to the BloodHound container's logs. The one-time generated
admin password appears in that log stream on first boot -- there's nothing
else to look up. **Ctrl+C stops the stack cleanly** (`docker stop` on all
three containers): containers and data both survive, so the next
`bloodhound-start` is a fast restart, not a rebuild.

Log in at `http://127.0.0.1:8080/ui/login` as `admin` once the stack is up.
Postgres and Neo4j logs aren't part of the attached stream; check them with
`docker logs bloodhound-ce-app-db` / `docker logs bloodhound-ce-graph-db`.

To run it in the background instead of attached:

```bash
nix run "github:borttappat/tools?dir=bloodhound-ce#bloodhound-detach"
```

```bash
nix run "github:borttappat/tools?dir=bloodhound-ce#bloodhound-stop"
```

`bloodhound-stop` also preserves data -- it's the same `docker stop` the
attached mode runs on Ctrl+C, just invoked directly for a detached run.

To permanently delete everything (containers, network, Postgres data, Neo4j
graph data -- all collected AD data, users, and sessions):

```bash
nix run "github:borttappat/tools?dir=bloodhound-ce#bloodhound-wipe"
```

This asks for an interactive `yes` confirmation. For scripted/non-interactive
use, set `BLOODHOUND_WIPE_CONFIRM=1` in the environment instead.

## Configuration

Override defaults with env vars (names match upstream's own
`docker-compose.yml`, so existing BloodHound CE docs still apply):

| Var | Default | Notes |
| --- | --- | --- |
| `POSTGRES_USER` | `bloodhound` | |
| `POSTGRES_PASSWORD` | `bloodhoundcommunityedition` | not a secret -- upstream's own lab default |
| `POSTGRES_DB` | `bloodhound` | |
| `NEO4J_USER` | `neo4j` | |
| `NEO4J_SECRET` | `bloodhoundcommunityedition` | not a secret -- upstream's own lab default |
| `BLOODHOUND_TAG` | `9.7.1` | pinned, not `latest` -- see below |
| `BLOODHOUND_PORT` | `8080` | UI/API, bound to `127.0.0.1` only |
| `NEO4J_WEB_PORT` | `7474` | Neo4j browser, bound to `127.0.0.1` only |
| `NEO4J_DB_PORT` | `7687` | Neo4j bolt, bound to `127.0.0.1` only |
| `bhe_disable_cypher_complexity_limit` | `false` | |
| `bhe_enable_cypher_mutations` | `false` | |
| `bhe_graph_query_memory_limit` | `2` | |
| `bhe_recreate_default_admin` | `false` | |

The default Postgres/Neo4j credentials are upstream's own lab defaults, not
secrets -- override them via env vars for anything beyond a short-lived
personal box.

`BLOODHOUND_TAG` is pinned to a specific release (currently `9.7.1`) rather
than upstream's floating `latest`, so a background image pull can't change
behavior mid-engagement -- same reasoning as `../nessus`'s image pin.
Postgres (`postgres:18`) and Neo4j (`neo4j:4.4.42`) are pinned the same way
upstream currently pins them.

## Architecture notes

- All three containers run on one user-defined bridge network
  (`bloodhound-ce`), and reach each other by container name via Docker's
  embedded DNS -- matching upstream's own `app-db`/`graph-db` service-name
  addressing (this flake's container names are `bloodhound-ce-app-db` /
  `bloodhound-ce-graph-db` / `bloodhound-ce-bloodhound`).
- Postgres and Neo4j data live in named Docker volumes
  (`bloodhound-ce-postgres-data`, `bloodhound-ce-neo4j-data`), not bind
  mounts.
- Everything is prefixed `bloodhound-ce-` (network, containers, volumes) so
  it can't collide with other Docker workloads on the same machine.

`nix run "github:..."` without a pinned revision caches the resolved commit
for up to an hour. If you just pushed a change and `nix run` still seems to
be running the old version, add `--refresh`:

```bash
nix run --refresh "github:borttappat/tools?dir=bloodhound-ce"
```
