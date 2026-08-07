# postman-drat

CLI tools for extracting and exporting structured data from emails and documents.

## Tools

### pst-export

Export PST/OST/PAB (Outlook) files to a clean directory structure.

```bash
./pst-export <mail.pst> [output_dir]
```

Internally this runs `pffexport` (from libpff) to do the actual PST parsing,
then reorganizes its output:

**Output:**
```
output/
├── manifest.txt           # Index of email items: Subject/From/To/Date
├── emails/                # pffexport's native per-item export, by PST folder
│   └── Top of Personal Folders/
│       └── Inbox/
│           └── Message00001/
│               ├── OutlookHeaders.txt
│               ├── Message.txt
│               ├── Recipients.txt
│               └── Attachments/
└── attachments/           # Every attachment, additionally fanned out by type
    ├── pdf/
    ├── docx/
    ├── xlsx/
    └── other/
```

Each email is a directory (pffexport's own format: separate headers, body,
and recipients files) rather than a single combined file, since that content
is already correctly parsed by pffexport itself. `manifest.txt` gives a flat,
scannable index (Subject/From/To/Date) across every email so you don't have
to open each directory by hand. Non-email PST items (contacts, calendar
entries, tasks, etc.) are exported by pffexport alongside the emails but are
not indexed in `manifest.txt`.

**Requires:** `pffexport` (from `libpff`), available via `nix develop` / `nix run` below.

---

### exfil

Universal document extractor for CLI.

```bash
./exfil <file>                    # Extract text from file
./exfil -r <dir>                  # Recursive extraction
./exfil -g "pattern" <file>       # Grep for pattern
./exfil -g "p" -r <dir>           # Grep recursively
```

**Supported formats:**

| Format | Tool |
|--------|------|
| PST/OST/PAB | `pst-export` (wraps `pffexport`, needs `libpff`) |
| PDF | `pdftotext` |
| DOCX | `pandoc` or `python-docx` |
| XLSX | `openpyxl` |
| PPTX | `python-pptx` |
| TXT/MD/JSON/XML/YAML | Direct |

PST extraction shells out to `pst-export` (looked up next to `exfil`, or on
`PATH`), exports to a scratch directory, and streams the resulting message
headers/bodies to stdout so it greps and pipes like every other format here.

---

## Workflow

```bash
# 1. Export PST to structured format
./pst-export exchange.pst ./out

# 2. Grep through extracted emails
./exfil -g "invoice" -r ./out/emails/

# 3. Find attachments
find ./out/attachments/pdf -name "*report*"
```

## Setup

### Nix flake, no clone required (recommended)

```bash
nix run github:borttappat/tools?dir=postman-drat#pst-export -- mail.pst ./output
nix run github:borttappat/tools?dir=postman-drat#exfil -- -g "invoice" -r ./output/emails/
```

Pulls a fully pinned environment (Python + openpyxl/python-docx/python-pptx,
pandoc, poppler, libpff) straight from the flake: no cloning, no venv, no
system package install.

### Nix (local checkout)

```bash
cd postman-drat
nix develop      # drops into a dev shell with the same pinned environment
chmod +x pst-export exfil
./pst-export mail.pst ./output
```

`nix-shell` still works too (see `shell.nix`), using the same pinned
`nixpkgs` packages rather than a runtime pip install.

### Manual Installation

Without Nix, install dependencies manually:

```bash
# Install system packages (macOS/Homebrew example)
brew install pandoc poppler libpff

# Install Python packages
pip install -r requirements.txt
```

Then run the tools directly:
```bash
./pst-export mail.pst ./output
./exfil document.pdf
```
