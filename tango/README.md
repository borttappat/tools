# Tango

```
 _______  _______   __    _  _______  _______ 
|       ||   _   ||  |  | ||       ||       |
|_     _||  |_|  ||   |_| ||    ___||   _   |
  |   |  |       ||       ||   | __ |  | |  |
  |   |  |       ||  _    ||   ||  ||  |_|  |
  |   |  |   _   || | |   ||   |_| ||       |
  |___|  |__| |__||_|  |__||_______||_______|

  file share reconnaissance and analysis tool
```

Tango crawls file shares, indexes their contents, and searches for sensitive
information such as credentials, secrets, API keys, and configuration data.

It supports two source types:

- **SMB shares** - authenticate and enumerate remote Windows/Samba shares
- **Local directories** - analyze file server dumps on disk (no authentication)

Rich document formats (PDF, Word, Excel, PowerPoint) are parsed via Apache Tika.

---

## Installation

### Nix (recommended)

```bash
cd tango
nix-shell
```

The shell hook creates a Python venv, installs all dependencies, and exports
`JAVA_HOME` so Tika can start its server process.

### Manual

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# System packages (Debian/Ubuntu)
sudo apt install binutils libmagic1 default-jre

# System packages (Arch)
sudo pacman -S binutils file jre-openjdk
```

> Tika downloads its server JAR (~60 MB) on first use. Java 8+ must be in PATH.

---

## Usage

### SMB mode

Index an SMB share, then search the downloaded files:

```bash
# Phase 1: walk (index shares and file metadata)
python3 tango.py walk -t 10.0.0.5 -u admin -p 'P@ssw0rd' -d CORP

# Phase 2: talk (download selected file types and search for keywords)
python3 tango.py talk --filetypes txt,ini,xml,cfg
python3 tango.py talk --filetypes pdf,docx,xlsx        # Tika extraction
python3 tango.py talk --filetypes txt --keywords-inline "password,secret,token"

# Auto-detect: runs walk if no index exists, talk if it does
python3 tango.py -t 10.0.0.5 -u admin -p 'P@ssw0rd'

# Combined: walk then talk in one go
python3 tango.py -t 10.0.0.5 -u admin -p 'P@ssw0rd' --filetypes txt,ini,pdf
```

Optional SMB flags:

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Domain name (default: WORKGROUP) |
| `--dc-ip IP` | Domain controller IP |
| `--override-filesize N` | Override 50 MB per-file limit (MB or "unlimited") |

### Local mode

Analyze a directory dump without any authentication:

```bash
# Phase 1: index the directory tree
python3 tango.py local-walk /mnt/fileserver/dump

# Phase 2: search indexed files for keywords
python3 tango.py local-talk /mnt/fileserver/dump --filetypes pdf,docx,xlsx,txt
python3 tango.py local-talk /mnt/fileserver/dump --keywords keywords.txt
python3 tango.py local-talk /mnt/fileserver/dump --keywords-inline "password,secret"
```

The `local-walk` and `local-talk` commands are independent - run walk first to
see what file types exist and how large they are, then pick what to search.

---

## Output files

### SMB mode

| File | Contents |
|------|----------|
| `smb_index_<ip>.txt` | Human-readable share index |
| `smb_index_<ip>.json` | Machine-readable index (used by talk phase) |
| `large_files_<ip>.txt` | Files over 50 MB, flagged for manual review |
| `downloads_<ip>/by_type/<ext>/RESULTS.txt` | Keyword matches per file type |
| `tango_<ip>_<timestamp>.log` | Full session log |

### Local mode

| File | Contents |
|------|----------|
| `local_index_<name>.txt` | Human-readable directory index |
| `local_index_<name>.json` | Machine-readable index (used by local-talk) |
| `local_results_<name>/by_type/<ext>/RESULTS.txt` | Keyword matches per file type |
| `tango_<name>_<timestamp>.log` | Full session log |

---

## File type handling

| Category | Extensions | Method |
|----------|------------|--------|
| Rich documents | pdf, doc, docx, xls, xlsx, ppt, pptx, odt, ods, odp, rtf, eml, msg | Apache Tika |
| Plain text | txt, ini, cfg, conf, log, xml, json, yaml, yml, env, toml, sql, py, sh, ps1, ... | Direct read |
| Archives | zip | Extract to temp dir, recurse |
| Binaries | exe, dll, msi, bin, so | `strings` command |
| Unknown | anything else | Attempt plain text read |

---

## Keywords

The default keyword set covers common credential patterns:

```
password, passwd, pass, pwd, secret, credential, cred,
api_key, apikey, api-key, private_key, privatekey, private-key,
ssh_key, sshkey, ssh-key, access_key, accesskey, access-key,
secret_key, secretkey, secret-key, key, token, bearer, auth,
authentication, username, user, account, admin, administrator, root,
database, db, connection, connectionstring, dsn, jdbc,
cert, certificate, pem, pfx, p12
```

Supply your own non-interactively with `--keywords <file>` or `--keywords-inline a,b,c`.

If neither flag is given, `talk`/`local-talk` show an interactive menu:

1. Use the default keyword set as-is
2. Use the default set plus extra keywords you type in
3. Enter custom keywords manually (only those — no defaults mixed in)
4. Load keywords from a file (only those — no defaults mixed in)
5. Use the saved list for this investigation, if one exists
6. Manage the saved list (view / add / remove / reset to defaults)

Whatever list you settle on, you can add extra keywords for just that run
(not saved), and optionally save the final list for reuse on this
investigation. Saved lists are per-investigation, named after the same
identifier used for the index file: `local_keywords_<name>.txt` next to
`local_index_<name>.json`, or `smb_keywords_<ip>.txt` next to
`smb_index_<ip>.json`.

Once a saved list exists, pass `--keywords-saved` to load it directly and
skip the menu entirely — useful for repeat runs on the same case.

---

## Requirements

- Python 3.8+
- Java 8+ (for Apache Tika)
- `strings` command from binutils (binary analysis)
- See `requirements.txt` for Python packages
