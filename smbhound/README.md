# SMBHound

SMBHound is a pentesting tool designed for systematically crawling SMB shares, documenting their structure, and identifying sensitive information such as credentials, secrets, keys, and backup files.

## Features

- **Two-Phase Architecture**: Walk (index) and Talk (analyze) phases
- **Comprehensive File Support**: Text files, binaries, archives, Office documents, databases
- **Intelligent Search**: Keyword-based search with context highlighting
- **Resume Capability**: Continue interrupted downloads
- **Multiple Output Formats**: Human-readable and machine-readable reports
- **Size Management**: Configurable file size limits with override options

## Installation & Setup

### Method 1: Using Nix (Recommended)

SMBHound includes a complete Nix development environment that provides all dependencies and tools:

```bash
# Clone and enter the SMBHound directory
cd smbhound

# Enter the Nix development environment
nix-shell

# The environment will automatically:
# - Create a Python virtual environment (./venv/)
# - Install all Python dependencies
# - Provide SMB server tools for testing
# - Include file creation utilities (gcc, sqlite, zip, etc.)

# Follow the quick start instructions shown in the shell
```

**Benefits of using Nix:**
- Completely isolated environment
- Reproducible builds across different systems
- No impact on your system's global packages
- Automatic dependency management
- Includes test SMB server setup

### Method 2: Manual Installation

If you don't have Nix, you can install dependencies manually:

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies
# Debian/Ubuntu:
sudo apt install binutils libmagic1 samba sqlite3

# macOS:
brew install libmagic samba sqlite3

# Arch Linux:
sudo pacman -S binutils file samba sqlite
```

### Setting Up Test Environment (Optional)

To test SMBHound locally, you can set up a minimal SMB server:

```bash
# In nix-shell environment:
./setup-test-smb.sh

# Start the test SMB server (in one terminal):
smbd -F -S -s ./smb-test/config/smb.conf

# Test SMBHound (in another terminal):
python3 smbhound.py walk -t 127.0.0.1:1445 -u guest -p ''
python3 smbhound.py talk --filetypes txt,ini,xml
```

### Basic Usage

```bash
# Auto-detect phase (walk if no index, talk if index exists)
./smbhound.py -t 10.0.0.5 -u admin -p password

# Explicit walk phase (indexing)
./smbhound.py walk -t 10.0.0.5 -u admin -p password

# Explicit talk phase (analysis)
./smbhound.py talk --filetypes txt,ini,xml

# Combined mode
./smbhound.py -t 10.0.0.5 -u admin -p password --filetypes txt,ini --keywords keywords.txt
```

## Architecture

### Walk Phase (`smbwalk.py`)
- Connects to SMB server
- Enumerates all shares and files
- Generates comprehensive index files
- Identifies large files requiring manual review

### Talk Phase (`smbtalk.py`)
- Downloads selected file types
- Searches for sensitive keywords
- Supports various file formats (text, binary, archives, Office docs)
- Generates detailed results with context

## Output Files

- `smb_index_<target>.txt` - Human-readable index
- `smb_index_<target>.json` - Machine-readable index
- `downloads_<target>/` - Downloaded files organized by type and share
- `downloads_<target>/by_type/*/RESULTS.txt` - Keyword search results
- `large_files_<target>.txt` - Large files requiring manual review
- `smbhound_<target>_<timestamp>.log` - Detailed execution log

## Examples

### Pentest Workflow
```bash
# 1. Index the target
./smbhound.py walk -t 10.0.0.5 -u admin -p 'P@ssw0rd' -d CORP

# 2. Review file types
cat smb_index_10.0.0.5.txt

# 3. Download and search config files
./smbhound.py talk --filetypes txt,ini,xml,cfg

# 4. Review findings
cat downloads_10.0.0.5/by_type/ini/RESULTS.txt
```

### Advanced Usage
```bash
# Large files override
./smbhound.py talk --filetypes bak --override-filesize 100

# Custom keywords
./smbhound.py talk --filetypes txt --keywords-inline "company,internal,secret"

# Resume interrupted session
./smbhound.py talk  # Auto-resumes if previous session detected
```

## File Type Support

SMBHound supports analysis of the following file types:

**Text Files**: txt, ini, xml, cfg, conf, log, json, yaml, yml, properties, env
**Database Files**: sql, db, sqlite, sqlite3, mdb
**Backup Files**: bak, backup, old, orig
**Archive Files**: zip, 7z, tar, gz, bz2, rar
**Office Documents**: docx, xlsx, pptx, doc, xls, ppt
**Scripts**: py, sh, bat, ps1, vbs, js
**Configuration**: config, settings, htaccess, gitignore

## Requirements

- Python 3.6+
- impacket >= 0.11.0
- python-magic >= 0.4.27
- colorama >= 0.4.6
- System: `strings` command (binutils package)

