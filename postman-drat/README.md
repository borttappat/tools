# postman-drat

CLI tools for extracting and exporting structured data from emails and documents.

## Tools

### pst-export

Export PST/Outlook files to a clean directory structure.

```bash
./pst-export <mail.pst> [output_dir]
```

**Output:**
```
output/
├── manifest.txt           # Full index of exported items
├── emails/                # Emails organized by PST folder
│   └── Inbox/
│       └── 2024-01-15__Subject.eml
└── attachments/           # Files sorted by type
    ├── pdf/
    ├── docx/
    ├── xlsx/
    └── other/
```

Each email file includes headers (`From`, `To`, `Subject`, `Date`, `Source Folder`) followed by the body. Attachments are named with their source email prefix for traceability.

**Requires:** `libpff` (available via `nix-shell -p libpff`)

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
| PST | `pffexport` (needs `libpff`) |
| PDF | `pdftotext` |
| DOCX | `pandoc` or `python-docx` |
| XLSX | `openpyxl` |
| PPTX | `python-pptx` (pip) |
| TXT/MD/JSON/XML/YAML | Direct |

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

### Using Nix (Recommended)

```bash
git clone https://github.com/borttappat/postman-drat.git
cd postman-drat
nix-shell          # Sets up Python venv + all dependencies
chmod +x pst-export exfil
./pst-export mail.pst ./output
```

The `nix-shell` automatically:
- Creates a Python virtual environment (`.venv/`)
- Installs all pip dependencies from `requirements.txt`
- Provides system tools: `pandoc`, `pdftotext`, `libpff`, and build tools

**Note:** On first entry or on machines without a `.venv` cache, `nix-shell` may take a minute to download and set up dependencies. Subsequent entries are faster.

**If nix-shell hangs:**
- Press `Ctrl+C` after 30+ seconds and it should continue
- Or manually install: `pip install -r requirements.txt` after entering the shell

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
