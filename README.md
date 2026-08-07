# tools

Personal security and tooling.

Each tool below has its own Nix flake, so it can be run on any Nix-capable
machine straight from GitHub, no cloning or manual dependency install
required. Add `--extra-experimental-features 'nix-command flakes'` to the
commands below if your `nix.conf` doesn't already have flakes enabled.

---

## tango

File share reconnaissance and keyword analysis tool.

Crawls SMB shares or local directory dumps, indexes file metadata, and searches
for sensitive information (credentials, API keys, secrets) across text files and
rich document formats (PDF, Word, Excel, PowerPoint via Apache Tika). Can also
pull embedded file metadata (authorship, GPS, software, timestamps) via
ExifTool with `--metadata`.

Run without cloning:

```bash
nix run "github:borttappat/tools?dir=tango" -- walk -t 10.0.0.5 -u admin -p 'pass'
```

```bash
nix run "github:borttappat/tools?dir=tango" -- talk --filetypes txt,ini,pdf,docx --metadata
```

```bash
nix run "github:borttappat/tools?dir=tango" -- local-walk /mnt/dump
```

```bash
nix run "github:borttappat/tools?dir=tango" -- local-talk /mnt/dump --filetypes pdf,docx,xlsx,txt --metadata
```

See `tango/README.md` for full usage.

---

## atlooter

Data collector for Atlassian Confluence Cloud and Jira Cloud.

Pulls pages, issues, comments, attachments, audit logs, and permissions via the
Atlassian REST APIs. All output is JSON with metadata wrapping for
integrity.

Needs one small local config file (not a clone) and credentials as env vars:

```bash
echo 'jira: {}' > jira_config.yaml
```

```bash
export JIRA_URL="https://your-domain.atlassian.net"
export JIRA_EMAIL="you@company.com"
export JIRA_TOKEN="your-api-token"
```

```bash
nix run "github:borttappat/tools?dir=atlooter#jira" -- --config jira_config.yaml --projects PROJ1 PROJ2
```

Confluence works the same way, with `confluence: {}` and `CONFLUENCE_URL`/`CONFLUENCE_EMAIL`/`CONFLUENCE_TOKEN`:

```bash
nix run "github:borttappat/tools?dir=atlooter#confluence" -- --config confluence_config.yaml --spaces DEMO DOC
```

See `atlooter/README.md` for full usage.

---

## postman-drat

CLI tools for extracting and searching data from PST/email archives and documents.

- **pst-export** - export PST/OST/PAB (Outlook) files to a clean directory structure, via `pffexport`
- **exfil** - extract text from PDF, DOCX, XLSX, PPTX, PST and grep through results

```bash
nix run "github:borttappat/tools?dir=postman-drat#pst-export" -- exchange.pst ./out
```

```bash
nix run "github:borttappat/tools?dir=postman-drat#exfil" -- -g "password" -r ./out/
```

See `postman-drat/README.md` for full usage.
