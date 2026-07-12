"""
Tango Local Talk Phase
Searches a locally indexed directory for keywords.
Supports plain text files and rich document formats via Apache Tika
(PDF, Word, Excel, PowerPoint, etc.)
"""

import os
import json
import time
import tempfile
import zipfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from logger import create_logger
from text_extractor import extract_text, TIKA_EXTENSIONS

TEXT_EXTENSIONS = {
    'txt', 'ini', 'cfg', 'conf', 'log', 'xml', 'json', 'yaml', 'yml',
    'properties', 'env', 'csv', 'tsv', 'md', 'rst', 'toml', 'hcl', 'tf',
    'py', 'sh', 'bash', 'bat', 'cmd', 'ps1', 'js', 'ts', 'php', 'rb',
    'java', 'c', 'h', 'cpp', 'cs', 'go', 'sql',
    'bak', 'old', 'backup', 'orig', 'config', 'settings',
    'gitignore', 'htaccess', 'npmrc', 'dockerignore'
}

ARCHIVE_EXTENSIONS = {'zip', '7z', 'tar', 'gz', 'bz2', 'rar'}
BINARY_EXTENSIONS = {'exe', 'dll', 'msi', 'bin', 'so', 'dylib'}


class LocalAnalyzer:
    def __init__(self, root_path, filetypes=None, keywords_file=None,
                 keywords_inline=None, override_filesize=None):
        self.root_path = Path(root_path).resolve()
        self.name = self.root_path.name
        self.logger = create_logger(self.name, "local-talk")
        self.start_time = time.time()

        self.selected_filetypes = self._parse_filetypes(filetypes) if filetypes else None
        self.keywords = self._parse_keywords(keywords_file, keywords_inline)
        self.max_filesize = self._parse_filesize_limit(override_filesize)

        self.index_data = None
        self.output_dir = f"local_results_{self.name}"

        self.stats = {
            "total_selected": 0,
            "searched": 0,
            "skipped_size": 0,
            "files_with_matches": 0,
            "total_matches": 0
        }

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _parse_filetypes(self, filetypes_str):
        return [ft.strip().lower() for ft in filetypes_str.split(',')]

    def _parse_keywords(self, keywords_file, keywords_inline):
        default_keywords = [
            'password', 'passwd', 'pass', 'pwd',
            'secret', 'credential', 'cred',
            'api_key', 'apikey', 'api-key',
            'private_key', 'privatekey', 'private-key',
            'ssh_key', 'sshkey', 'ssh-key',
            'access_key', 'accesskey', 'access-key',
            'secret_key', 'secretkey', 'secret-key',
            'key', 'token', 'bearer', 'auth', 'authentication',
            'username', 'user', 'account',
            'admin', 'administrator', 'root',
            'database', 'db', 'connection', 'connectionstring',
            'dsn', 'jdbc', 'cert', 'certificate', 'pem', 'pfx', 'p12'
        ]

        keywords = []
        if keywords_file:
            try:
                with open(keywords_file, 'r') as f:
                    keywords = [line.strip().lower() for line in f if line.strip()]
            except FileNotFoundError:
                self.logger.error(f"Keywords file not found: {keywords_file}")
                keywords = default_keywords
        elif keywords_inline:
            keywords = [kw.strip().lower() for kw in keywords_inline.split(',')]
        else:
            keywords = default_keywords

        seen = set()
        unique = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                unique.append(kw)
        return unique

    def _parse_filesize_limit(self, override_str):
        if not override_str:
            return 50 * 1024 * 1024
        if override_str.lower() == 'unlimited':
            return float('inf')
        try:
            return int(override_str) * 1024 * 1024
        except ValueError:
            self.logger.warning(f"Invalid filesize override: {override_str}. Using default 50MB.")
            return 50 * 1024 * 1024

    def format_size(self, size_bytes):
        if size_bytes == 0:
            return "0 B"
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(size_bytes)
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        return f"{int(size)} {units[unit_index]}" if unit_index == 0 else f"{size:.1f} {units[unit_index]}"

    # -------------------------------------------------------------------------
    # Index loading
    # -------------------------------------------------------------------------

    def load_index(self):
        """Load the local JSON index produced by local-walk."""
        index_file = f"local_index_{self.name}.json"

        if not os.path.exists(index_file):
            self.logger.critical(
                f"No index found: {index_file}\n"
                f"Run 'tango local-walk {self.root_path}' first."
            )
            return False

        try:
            with open(index_file, 'r') as f:
                self.index_data = json.load(f)
            metadata = self.index_data.get('metadata', {})
            self.logger.info(f"Index loaded: {index_file}")
            self.logger.info(f"Index date: {metadata.get('scan_timestamp', 'Unknown')}")
            self.logger.info(f"Files in index: {self.index_data['summary']['total_files']:,}")
            return True
        except Exception as e:
            self.logger.critical(f"Failed to load index: {e}")
            return False

    # -------------------------------------------------------------------------
    # Interactive selections
    # -------------------------------------------------------------------------

    def interactive_filetype_selection(self):
        """Let user pick file types to search, or use --filetypes."""
        if self.selected_filetypes:
            return self.selected_filetypes

        file_types = self.index_data.get('file_types', {})
        if not file_types:
            self.logger.error("No file types found in index")
            return []

        print("\n" + "=" * 80)
        print("Tango Local Talk - File Type Selection")
        print("=" * 80)
        print(f"Root path: {self.root_path}")
        print(f"\nAvailable file types (sorted by count):\n")

        sorted_types = sorted(file_types.items(), key=lambda x: x[1]['count'], reverse=True)
        type_options = {}

        for i, (ext, info) in enumerate(sorted_types, 1):
            ext_display = f".{ext}" if ext else "(no extension)"
            size_str = self.format_size(info['total_size'])
            tags = []
            if ext in TIKA_EXTENSIONS:
                tags.append("TIKA")
            elif ext in TEXT_EXTENSIONS:
                tags.append("TEXT")
            elif ext in ARCHIVE_EXTENSIONS:
                tags.append("ARCHIVE")
            elif ext in BINARY_EXTENSIONS:
                tags.append("BINARY")
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            print(f"{i:3}. {ext_display:<14} {info['count']:>6} files    {size_str:>10}{tag_str}")
            type_options[str(i)] = ext

        print("\nExtraction methods:")
        print("  TIKA    - Apache Tika (PDF, Word, Excel, PowerPoint, etc.)")
        print("  TEXT    - Direct line-by-line reading")
        print("  ARCHIVE - Extraction + recursive search")
        print("  BINARY  - String extraction via 'strings' command")

        while True:
            try:
                selection = input("\nEnter selection (comma-separated numbers, 'all', or 'q'): ").strip()

                if selection.lower() == 'q':
                    return []
                elif selection.lower() == 'all':
                    return list(file_types.keys())
                else:
                    selections = [s.strip() for s in selection.split(',')]
                    selected = []
                    for sel in selections:
                        if sel in type_options:
                            selected.append(type_options[sel])
                        elif sel.lstrip('.') in file_types:
                            selected.append(sel.lstrip('.'))
                        else:
                            print(f"  Unknown: {sel}")

                    if selected:
                        total_files = sum(file_types[e]['count'] for e in selected if e in file_types)
                        total_size = sum(file_types[e]['total_size'] for e in selected if e in file_types)
                        print(f"\nSelected: {', '.join('.' + e for e in selected)}")
                        print(f"Total: {total_files} files, {self.format_size(total_size)}")

                        confirm = input("Continue? [y/N]: ").strip().lower()
                        if confirm in ['y', 'yes']:
                            return selected

            except KeyboardInterrupt:
                print("\nAborted.")
                return []

    def interactive_keyword_input(self):
        """Let user configure keywords, or use --keywords / --keywords-inline."""
        if self.keywords:
            return self.keywords

        print("\n" + "=" * 80)
        print("Keyword Search Configuration")
        print("=" * 80)
        print("\n  1. Enter keywords manually (comma-separated)")
        print("  2. Load keywords from file")
        print("  3. Use default keyword set (recommended)")

        while True:
            try:
                choice = input("\nYour choice [1/2/3]: ").strip()

                if choice == '1':
                    raw = input("Enter keywords (comma-separated): ").strip()
                    if raw:
                        return [kw.strip().lower() for kw in raw.split(',')]

                elif choice == '2':
                    file_path = input("Enter keywords file path: ").strip()
                    try:
                        with open(file_path, 'r') as f:
                            return [line.strip().lower() for line in f if line.strip()]
                    except FileNotFoundError:
                        print(f"  File not found: {file_path}")

                elif choice == '3':
                    defaults = self._parse_keywords(None, None)
                    print(f"\n  Using {len(defaults)} default keywords.")
                    extra = input("  Add extra keywords (comma-separated, or Enter to skip): ").strip()
                    if extra:
                        defaults.extend([kw.strip().lower() for kw in extra.split(',')])
                    confirm = input("Proceed? [Y/n]: ").strip().lower()
                    if confirm in ['', 'y', 'yes']:
                        return defaults
                else:
                    print("  Invalid choice.")

            except KeyboardInterrupt:
                print("\nAborted.")
                return []

    # -------------------------------------------------------------------------
    # Keyword search methods
    # -------------------------------------------------------------------------

    def _search_lines(self, lines, source_type=None):
        """Search a list of text lines for keywords. Returns match dicts."""
        matches = []
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.rstrip('\n')
            if not line_stripped.strip():
                continue
            line_lower = line_stripped.lower()

            for keyword in self.keywords:
                if keyword not in line_lower:
                    continue
                positions = []
                start = 0
                while True:
                    pos = line_lower.find(keyword, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
                if positions:
                    ctx_before = lines[line_num - 2].strip() if line_num > 1 else ""
                    ctx_after = lines[line_num].strip() if line_num < len(lines) else ""
                    entry = {
                        'line_number': line_num,
                        'line_content': line_stripped.strip(),
                        'matched_keyword': keyword,
                        'context_before': ctx_before,
                        'context_after': ctx_after,
                        'keyword_positions': positions,
                    }
                    if source_type:
                        entry['source_type'] = source_type
                    matches.append(entry)
        return matches

    def search_file(self, file_path):
        """Route a file to the appropriate search method."""
        ext = Path(file_path).suffix.lower().lstrip('.')
        size = os.path.getsize(file_path)

        if size > self.max_filesize:
            return None  # skipped

        if ext in TIKA_EXTENSIONS:
            return self._search_tika(file_path)
        elif ext in TEXT_EXTENSIONS or ext == '':
            return self._search_text(file_path)
        elif ext in ARCHIVE_EXTENSIONS:
            return self._search_archive(file_path, ext)
        elif ext in BINARY_EXTENSIONS:
            return self._search_binary(file_path)
        else:
            # Try as text for unknown extensions
            return self._search_text(file_path)

    def _search_tika(self, file_path):
        """Extract text via Tika then search line by line."""
        text = extract_text(file_path, self.logger)
        if not text:
            return []
        lines = text.splitlines()
        return self._search_lines(lines, source_type='tika_extracted')

    def _search_text(self, file_path):
        """Search plain text file line by line."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return self._search_lines(lines)
        except Exception as e:
            self.logger.debug(f"Text read failed for {file_path}: {e}")
            return []

    def _search_binary(self, file_path):
        """Extract printable strings then search."""
        matches = []
        try:
            result = subprocess.run(
                ['strings', '-a', '-n', '8', file_path],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                matches = self._search_lines(lines, source_type='binary_strings')
        except subprocess.TimeoutExpired:
            self.logger.warning(f"strings timeout: {file_path}")
        except FileNotFoundError:
            self.logger.warning("'strings' not found. Install binutils.")
        except Exception as e:
            self.logger.debug(f"Binary search error {file_path}: {e}")
        return matches

    def _search_archive(self, file_path, ext):
        """Extract archive to temp dir and search contents."""
        matches = []
        size = os.path.getsize(file_path)
        if size > 10 * 1024 * 1024:
            self.logger.info(f"Archive too large to auto-extract (>10MB): {file_path}")
            return matches

        try:
            if ext == 'zip':
                with zipfile.ZipFile(file_path, 'r') as zf:
                    with tempfile.TemporaryDirectory() as tmp:
                        zf.extractall(tmp)
                        for root, _, files in os.walk(tmp):
                            for name in files:
                                extracted = os.path.join(root, name)
                                inner_ext = Path(name).suffix.lower().lstrip('.')
                                try:
                                    if inner_ext in TIKA_EXTENSIONS:
                                        inner_matches = self._search_tika(extracted)
                                    else:
                                        inner_matches = self._search_text(extracted)
                                    for m in inner_matches:
                                        m['source_type'] = 'archive_extracted'
                                        m['extracted_file'] = name
                                    matches.extend(inner_matches)
                                except Exception as e:
                                    self.logger.debug(f"Error searching {name}: {e}")
        except Exception as e:
            self.logger.debug(f"Archive error {file_path}: {e}")

        return matches

    # -------------------------------------------------------------------------
    # Results output
    # -------------------------------------------------------------------------

    def highlight_keywords(self, line, keywords):
        line_lower = line.lower()
        highlight = [' '] * len(line)
        for keyword in keywords:
            start = 0
            while True:
                pos = line_lower.find(keyword, start)
                if pos == -1:
                    break
                for i in range(pos, min(pos + len(keyword), len(highlight))):
                    highlight[i] = '^'
                start = pos + 1
        return ''.join(highlight).rstrip()

    def generate_results_file(self, file_type, matches_by_file):
        """Write RESULTS.txt for a given file type."""
        results_file = f"{self.output_dir}/by_type/{file_type}/RESULTS.txt"
        os.makedirs(os.path.dirname(results_file), exist_ok=True)

        total_files = len(matches_by_file)
        files_with_matches = len([f for f, m in matches_by_file.items() if m])
        total_matches = sum(len(m) for m in matches_by_file.values())

        with open(results_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("Tango Local Keyword Search Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"File Type:      .{file_type}\n")
            f.write(f"Root Path:      {self.root_path}\n")
            f.write(f"Scan Date:      {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"Files Scanned:  {total_files}\n")
            f.write(f"Files Matched:  {files_with_matches}\n")
            f.write(f"Total Matches:  {total_matches}\n")
            if file_type in TIKA_EXTENSIONS:
                f.write(f"Extraction:     Apache Tika\n")
            f.write(f"\nKeywords Used ({len(self.keywords)}):\n")
            keywords_str = ", ".join(self.keywords)
            while len(keywords_str) > 70:
                split_pos = keywords_str.rfind(', ', 0, 70)
                if split_pos == -1:
                    split_pos = 70
                f.write(f"  {keywords_str[:split_pos]}\n")
                keywords_str = keywords_str[split_pos:].lstrip(', ')
            if keywords_str:
                f.write(f"  {keywords_str}\n")
            f.write("\n" + "=" * 80 + "\n\n")

            for file_path, matches in matches_by_file.items():
                if not matches:
                    continue

                f.write("#" * 80 + "\n")
                rel = Path(file_path).relative_to(self.root_path) if Path(file_path).is_relative_to(self.root_path) else file_path
                size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                f.write(f"FILE: {rel}\n")
                f.write(f"PATH: {file_path}\n")
                f.write(f"SIZE: {self.format_size(size)}\n")
                matched_keywords = list(set(m['matched_keyword'] for m in matches))
                f.write(f"MATCHES: {len(matches)} (keywords: {', '.join(matched_keywords)})\n")
                f.write("#" * 80 + "\n\n")

                for i, match in enumerate(matches, 1):
                    f.write(f"[Match #{i} - Line {match['line_number']}]\n")
                    if match.get('context_before'):
                        f.write(f"  {match['line_number']-1}: {match['context_before']}\n")
                    f.write(f"  {match['line_number']}: {match['line_content']}\n")
                    highlight_str = self.highlight_keywords(match['line_content'], [match['matched_keyword']])
                    if highlight_str.strip():
                        f.write(f"  {' ' * len(str(match['line_number']))}: {highlight_str}\n")
                    if match.get('context_after'):
                        f.write(f"  {match['line_number']+1}: {match['context_after']}\n")
                    f.write("\n")

                # Per-file summary
                f.write("-" * 80 + "\n")
                pass_matches = [m for m in matches if 'pass' in m['matched_keyword']]
                key_matches = [m for m in matches if 'key' in m['matched_keyword']]
                admin_matches = [m for m in matches if 'admin' in m['matched_keyword']]
                if pass_matches:
                    f.write(f"  Credentials: {len(pass_matches)} password fields\n")
                if key_matches:
                    f.write(f"  Keys/Tokens: {len(key_matches)} references\n")
                if admin_matches:
                    f.write(f"  Admin refs:  {len(admin_matches)}\n")
                if pass_matches or key_matches:
                    f.write("  Priority: HIGH\n")
                elif admin_matches:
                    f.write("  Priority: MEDIUM\n")
                else:
                    f.write("  Priority: LOW\n")
                f.write("-" * 80 + "\n\n")

            f.write("=" * 80 + "\n")
            f.write("End of Results\n")
            f.write("=" * 80 + "\n")
            f.write("Generated by Tango v1.1.0\n")
            f.write(f"Report date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

        return results_file

    # -------------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------------

    def analyze(self):
        """Main local-talk execution."""
        try:
            if not self.load_index():
                return False

            self.selected_filetypes = self.interactive_filetype_selection()
            if not self.selected_filetypes:
                self.logger.info("No file types selected.")
                return False

            self.keywords = self.interactive_keyword_input()
            if not self.keywords:
                self.logger.info("No keywords provided.")
                return False

            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(f"{self.output_dir}/by_type", exist_ok=True)

            # Filter files from index
            all_files = self.index_data.get('files', [])
            selected_files = [
                fi for fi in all_files
                if fi.get('extension', '') in self.selected_filetypes
            ]

            if not selected_files:
                self.logger.info("No files match the selected types.")
                return False

            self.logger.info("=" * 60)
            self.logger.info("[SEARCH] Starting local keyword search")
            self.logger.info("=" * 60)
            self.logger.info(f"File types: {', '.join('.' + t for t in self.selected_filetypes)}")
            self.logger.info(f"Files to search: {len(selected_files)}")
            self.logger.info(f"Keywords: {len(self.keywords)}")

            tika_types = [t for t in self.selected_filetypes if t in TIKA_EXTENSIONS]
            if tika_types:
                self.logger.info(f"Tika extraction for: {', '.join('.' + t for t in tika_types)}")

            # Group by extension
            files_by_type = defaultdict(list)
            for fi in selected_files:
                files_by_type[fi['extension']].append(fi)

            for file_type, files in files_by_type.items():
                self.logger.info(f"\n[SEARCH] .{file_type} ({len(files)} files)")

                matches_by_file = {}

                for i, fi in enumerate(files, 1):
                    file_path = fi['path']

                    if not os.path.exists(file_path):
                        self.logger.warning(f"File no longer exists: {file_path}")
                        continue

                    size = fi.get('size', 0)
                    if size > self.max_filesize:
                        self.stats['skipped_size'] += 1
                        continue

                    matches = self.search_file(file_path)
                    if matches is None:
                        self.stats['skipped_size'] += 1
                        continue

                    matches_by_file[file_path] = matches
                    self.stats['searched'] += 1

                    if matches:
                        self.stats['files_with_matches'] += 1
                        self.stats['total_matches'] += len(matches)
                        self.logger.match(f"{fi['relative_path']} ({len(matches)} matches)")

                    if i % 50 == 0 or i == len(files):
                        pct = (i / len(files)) * 100
                        self.logger.info(f"  Progress: {i}/{len(files)} ({pct:.0f}%)")

                if matches_by_file:
                    results_file = self.generate_results_file(file_type, matches_by_file)
                    found = sum(len(m) for m in matches_by_file.values())
                    matched_files = len([f for f, m in matches_by_file.items() if m])
                    self.logger.info(f"  [RESULTS] {matched_files} files with {found} matches → {results_file}")

            duration = time.time() - self.start_time
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"

            self.logger.info("\n" + "=" * 60)
            self.logger.info("[COMPLETE] Local Search Finished")
            self.logger.info("=" * 60)
            self.logger.info(f"Duration: {duration_str}")
            self.logger.info(f"Files searched: {self.stats['searched']} ({self.stats['skipped_size']} skipped, too large)")
            self.logger.info(f"Keyword matches: {self.stats['total_matches']} in {self.stats['files_with_matches']} files")
            self.logger.info(f"Results: {self.output_dir}/")

            self.logger.session_end(duration_str)
            return True

        except Exception as e:
            self.logger.critical(f"Local analyze failed: {e}")
            import traceback
            traceback.print_exc()
            return False
