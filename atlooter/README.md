# atlooter

Data collector for Atlassian Confluence Cloud and Jira Cloud.

Pulls pages, issues, comments, attachments, audit logs, permissions, and user
activity via the Atlassian REST APIs. All output is JSON with metadata
wrapping (collection timestamp, request log, tool version) for integrity.

---

## Quick start

### Nix flake, no clone required (recommended)

The collector config isn't bundled into the nix package, so you need one
small local YAML file per service (not a clone, just a placeholder, since
all real credentials come from env vars regardless of file content):

```bash
echo 'confluence: {}' > confluence_config.yaml
```

```bash
echo 'jira: {}' > jira_config.yaml
```

Set Confluence credentials:

```bash
export CONFLUENCE_URL="https://your-domain.atlassian.net"
export CONFLUENCE_EMAIL="your-email@company.com"
export CONFLUENCE_TOKEN="your-api-token"
```

Set Jira credentials:

```bash
export JIRA_URL="https://your-domain.atlassian.net"
export JIRA_EMAIL="your-email@company.com"
export JIRA_TOKEN="your-api-token"
```

Get an API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Run:

```bash
nix run "github:borttappat/tools?dir=atlooter#confluence" -- --config confluence_config.yaml
```

```bash
nix run "github:borttappat/tools?dir=atlooter#jira" -- --config jira_config.yaml
```

Limit scope:

```bash
nix run "github:borttappat/tools?dir=atlooter#confluence" -- --config confluence_config.yaml --spaces DEMO DOC
```

```bash
nix run "github:borttappat/tools?dir=atlooter#jira" -- --config jira_config.yaml --projects PROJ1 PROJ2
```

```bash
nix run "github:borttappat/tools?dir=atlooter#jira" -- --config jira_config.yaml --jql "project = PROJ AND created >= '2024-01-01'"
```

### Nix (local checkout)

```bash
cd atlooter
nix develop
```

```bash
python scripts/run_confluence.py --config config/confluence_config.yaml
```

```bash
python scripts/run_jira.py --config config/jira_config.yaml
```

`nix-shell` still works too (see `shell.nix`), using the same pinned packages.

---

## What is collected

### Confluence

| Collector | Data | Output |
|-----------|------|--------|
| `pages` | Full page content (storage format), version history | `{KEY}/pages/` |
| `comments` | All page comments with author/timestamp | `{KEY}/comments/` |
| `restrictions` | Read/update permissions per page | `{KEY}/restrictions/` |
| `attachments` | Attachment metadata + optional file download | `{KEY}/attachments/` |
| `spaces` | Space metadata and permissions | `spaces/` |
| `templates` | Space and global templates | `templates/` |
| `audit_log` | Full Confluence audit trail | `audit/` |

### Jira

| Collector | Data | Output |
|-----------|------|--------|
| `issues` | Full issue data, custom fields, change history, comments, worklogs | `{KEY}/issues.json` |
| `comments` | All comments per issue | `{KEY}/all_comments.json` |
| `worklogs` | Time tracking entries | `{KEY}/all_worklogs.json` |
| `links` | Issue-to-issue relationships | `{KEY}/all_links.json` |
| `remote_links` | Links to external resources and Confluence pages | `{KEY}/remote_links.json` |
| `attachments` | Attachment metadata + optional file download | `{KEY}/attachments/` |
| `watchers` | Who is watching each issue | `{KEY}/watchers.json` |
| `epics` | Epic structure per project | `{KEY}/epics.json` |
| `project_meta` | Versions/releases, components, roles, permission scheme | `{KEY}/project_meta.json` |
| `sprints` | Board and sprint data | `all_boards.json`, `all_sprints.json` |
| `audit_log` | Full Jira audit trail | `audit/audit_log_{timestamp}.json` |
| `users` | All users in the instance | `global/users.json` |
| `fields` | Custom field definitions | `global/fields.json` |
| `priorities` | Priority scheme | `global/priorities.json` |
| `statuses` | All issue statuses | `global/statuses.json` |

---

## Output format

All files are JSON with forensic metadata wrapping:

```json
{
  "_metadata": {
    "collection_timestamp": "2024-01-15T10:30:00Z",
    "collection_type": "project_issues",
    "format": "json",
    "tool_version": "1.0.0"
  },
  "_request_log": [...],
  "data": { ... }
}
```

Output goes to `output/confluence/` and `output/jira/` by default (configurable in YAML).

---

## Directory structure

```
atlooter/
├── config/
│   ├── confluence_config.yaml
│   └── jira_config.yaml
├── scripts/
│   ├── confluence_collector/
│   │   ├── api_client.py
│   │   ├── collectors/
│   │   │   ├── pages.py
│   │   │   ├── comments.py
│   │   │   ├── restrictions.py
│   │   │   ├── attachments.py
│   │   │   ├── spaces.py
│   │   │   ├── templates.py
│   │   │   └── audit.py
│   │   └── utils/
│   ├── jira_collector/
│   │   ├── api_client.py
│   │   ├── collectors/
│   │   │   ├── issues.py
│   │   │   ├── comments.py
│   │   │   ├── worklogs.py
│   │   │   ├── links.py
│   │   │   ├── remote_links.py
│   │   │   ├── attachments.py
│   │   │   ├── watchers.py
│   │   │   ├── sprints.py
│   │   │   ├── project_meta.py
│   │   │   └── audit.py
│   │   └── utils/
│   ├── run_confluence.py
│   └── run_jira.py
└── output/
    ├── confluence/
    └── jira/
        ├── global/
        ├── {PROJECT_KEY}/
        └── audit/
```

---

## CLI options

```
--config PATH          Config file path
--projects KEY ...     Jira: specific projects (default: all)
--spaces KEY ...       Confluence: specific spaces (default: all)
--jql QUERY            Jira: JQL filter for issues
--no-download-files    Skip downloading attachment files
--verbose              Debug logging
```

---

## Collector config

Each collector can be toggled in the YAML config:

```yaml
collectors:
  pages: true
  comments: true
  restrictions: true
  attachments: true
  spaces: true
  templates: true
  audit_log: true
```

---

## Troubleshooting

**Authentication errors** - check tokens are valid and the user has read access to the target projects/spaces.

**Missing data** - review `output/jira/collection_summary.json` for per-collector error messages.

**Sprints showing 0** - sprint data only exists on Scrum boards; Kanban boards have no sprints.

**Rate limiting** - increase `backoff_factor` or reduce `max_per_minute` in the config.
