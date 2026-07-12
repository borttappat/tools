# tools

Personal security and tooling.

---

## tango

File share reconnaissance and keyword analysis tool.

Crawls SMB shares or local directory dumps, indexes file metadata, and searches
for sensitive information (credentials, API keys, secrets) across text files and
rich document formats (PDF, Word, Excel, PowerPoint via Apache Tika).

```bash
# SMB mode
python3 tango.py walk -t 10.0.0.5 -u admin -p 'pass'
python3 tango.py talk --filetypes txt,ini,pdf,docx

# Local mode (no auth - for file server dumps on disk)
python3 tango.py local-walk /mnt/dump
python3 tango.py local-talk /mnt/dump --filetypes pdf,docx,xlsx,txt
```

See `tango/README.md` for full usage.

---

## atlooter

Data collector for Atlassian Confluence Cloud and Jira Cloud.

Pulls pages, issues, comments, attachments, audit logs, and permissions via the
Atlassian REST APIs. All output is JSON with metadata wrapping for
integrity.

```bash
cd atlooter && nix-shell

python scripts/run_confluence.py --spaces DEMO DOC
python scripts/run_jira.py --projects PROJ1 PROJ2
python scripts/run_jira.py --jql "project = PROJ AND created >= '2024-01-01'"
```

See `atlooter/README.md` for full usage.

---

## postman-drat

CLI tools for extracting and searching data from PST/email archives and documents.

- **pst-export** - export PST/Outlook files to a clean directory structure
- **exfil** - extract text from PDF, DOCX, XLSX, PPTX, PST and grep through results

```bash
./pst-export exchange.pst ./out
./exfil -g "password" -r ./out/
```

See `postman-drat/README.md` for full usage.
