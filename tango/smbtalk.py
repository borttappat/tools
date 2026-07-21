"""
Tango SMB Talk Phase
Downloads selected files and searches for sensitive information
"""

import os
import json
import time
import tempfile
import subprocess
import zipfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from impacket.smbconnection import SMBConnection
import magic

from logger import create_logger
from text_extractor import extract_text, TIKA_EXTENSIONS
import keywords as kwmod

# Extensions handled by Tika (rich document formats)
RICH_DOC_EXTENSIONS = TIKA_EXTENSIONS


class SMBTalker:
    def __init__(self, target_ip=None, filetypes=None, keywords_file=None,
                 keywords_inline=None, override_filesize=None, keywords_saved=False):
        if target_ip is None:
            target_ip = self.detect_target_from_index()

        self.target_ip = target_ip
        self.logger = create_logger(target_ip, "smb-talk")
        self.start_time = time.time()

        self.selected_filetypes = self.parse_filetypes(filetypes) if filetypes else None
        self.keywords = self.parse_keywords(keywords_file, keywords_inline) if (keywords_file or keywords_inline) else []
        self.keywords_saved = keywords_saved
        self.max_filesize = self.parse_filesize_limit(override_filesize)

        self.index_data = None
        self.credentials = None

        self.downloaded_files = []
        self.keyword_matches = defaultdict(list)
        self.skipped_files = []
        self.download_stats = {
            "total_files": 0,
            "downloaded_files": 0,
            "skipped_files": 0,
            "total_size": 0,
            "matches_found": 0,
            "files_with_matches": 0
        }

        self.output_dir = f"downloads_{self.target_ip}"
        self.smb_conn = None

    def detect_target_from_index(self):
        """Try to detect target IP from existing index files"""
        for file in os.listdir('.'):
            if file.startswith('smb_index_') and file.endswith('.json'):
                return file.replace('smb_index_', '').replace('.json', '')
        return None

    def parse_filetypes(self, filetypes_str):
        if not filetypes_str:
            return None
        return [ft.strip().lower() for ft in filetypes_str.split(',')]

    def parse_keywords(self, keywords_file, keywords_inline):
        if keywords_file:
            try:
                keywords = kwmod.parse_keywords_file(keywords_file)
            except FileNotFoundError:
                self.logger.error(f"Keywords file not found: {keywords_file}")
                keywords = kwmod.DEFAULT_KEYWORDS
        elif keywords_inline:
            keywords = [kw.strip().lower() for kw in keywords_inline.split(',')]
        else:
            keywords = kwmod.DEFAULT_KEYWORDS

        return kwmod.dedupe(keywords)

    def parse_filesize_limit(self, override_str):
        if not override_str:
            return 50 * 1024 * 1024
        if override_str.lower() == 'unlimited':
            return float('inf')
        try:
            return int(override_str) * 1024 * 1024
        except ValueError:
            self.logger.warning(f"Invalid filesize override: {override_str}. Using default 50MB.")
            return 50 * 1024 * 1024

    def load_index(self):
        """Load the SMB index file"""
        index_file = f"smb_index_{self.target_ip}.json"

        if not os.path.exists(index_file):
            self.logger.critical(f"No index found for {self.target_ip}. Run 'tango walk' first.")
            return False

        try:
            with open(index_file, 'r') as f:
                self.index_data = json.load(f)

            metadata = self.index_data.get('metadata', {})
            self.credentials = {
                'username': metadata.get('username'),
                'domain': metadata.get('domain', 'WORKGROUP')
            }

            self.logger.info(f"Index loaded: {index_file}")
            self.logger.info(f"Index date: {metadata.get('scan_timestamp', 'Unknown')}")
            return True

        except Exception as e:
            self.logger.critical(f"Failed to load index: {e}")
            return False

    def interactive_filetype_selection(self):
        """Interactive file type selection if not specified"""
        if self.selected_filetypes:
            return self.selected_filetypes

        print("\n" + "=" * 80)
        print("Tango Talk Phase - File Type Selection")
        print("=" * 80)
        print(f"Target: {self.target_ip}")

        file_types = self.index_data.get('file_types', {})
        if not file_types:
            self.logger.error("No file types found in index")
            return []

        print("\nAvailable file types (sorted by count):\n")
        sorted_types = sorted(file_types.items(), key=lambda x: x[1]['count'], reverse=True)

        type_options = {}
        for i, (ext, info) in enumerate(sorted_types, 1):
            ext_display = f".{ext}" if ext else "(no extension)"
            size_str = self.format_size(info['total_size'])

            recommendations = []
            if ext in ['txt', 'ini', 'xml', 'cfg', 'conf']:
                recommendations.append("HIGH VALUE")
            elif ext in ['bak', 'old', 'backup']:
                recommendations.append("HIGH PRIORITY")
            elif ext in ['pdf', 'docx', 'xlsx', 'doc', 'xls', 'pptx']:
                recommendations.append("TIKA EXTRACTION")
            elif ext in ['exe', 'msi', 'dll']:
                recommendations.append("REVIEW NEEDED")
            elif ext in ['db', 'sqlite', 'mdb']:
                recommendations.append("MANUAL REVIEW")

            rec_str = f" [{', '.join(recommendations)}]" if recommendations else ""
            print(f"{i:2}. {ext_display:<12} {info['count']:>6} files    {size_str:>10}{rec_str}")
            type_options[str(i)] = ext

        print(f"\nRecommendations:")
        print(f"  - Start with: txt, ini, xml, cfg (small, high-value)")
        print(f"  - Rich docs:  pdf, docx, xlsx (Tika text extraction)")
        print(f"  - Review later: bak, exe, msi (larger, may need manual analysis)")

        while True:
            try:
                selection = input(f"\nEnter selection (comma-separated numbers, 'all', or 'q' to quit): ").strip()

                if selection.lower() == 'q':
                    return []
                elif selection.lower() == 'all':
                    return list(file_types.keys())
                else:
                    selections = [s.strip() for s in selection.split(',')]
                    selected_types = []

                    for sel in selections:
                        if sel in type_options:
                            selected_types.append(type_options[sel])
                        elif sel.lstrip('.') in file_types:
                            selected_types.append(sel.lstrip('.'))
                        elif sel in file_types:
                            selected_types.append(sel)
                        else:
                            print(f"Invalid selection: {sel}")
                            continue

                    if selected_types:
                        print(f"\nYou selected:")
                        total_files = 0
                        total_size = 0

                        for ext in selected_types:
                            info = file_types[ext]
                            tika_note = " (Tika)" if ext in RICH_DOC_EXTENSIONS else ""
                            print(f"  - .{ext}{tika_note} ({info['count']} files, {self.format_size(info['total_size'])})")
                            total_files += info['count']
                            total_size += info['total_size']

                        print(f"\nTotal: {total_files} files, {self.format_size(total_size)}")

                        large_types = [ext for ext in selected_types if file_types[ext]['total_size'] > self.max_filesize]
                        if large_types:
                            print(f"\nWARNING: Some types include files >{self.format_size(self.max_filesize)}. Large files will be skipped.")

                        confirm = input("\nContinue? [y/N]: ").strip().lower()
                        if confirm in ['y', 'yes']:
                            return selected_types

            except KeyboardInterrupt:
                print("\nAborted.")
                return []
            except Exception as e:
                print(f"Error: {e}")
                continue

    def interactive_keyword_input(self):
        """Interactive keyword input, or use --keywords / --keywords-inline / --keywords-saved."""
        if self.keywords:
            return self.keywords

        if self.keywords_saved:
            loaded = kwmod.load_saved_keywords('smb', self.target_ip)
            if loaded is None:
                self.logger.error(
                    f"No saved keyword list found at {kwmod.saved_keywords_path('smb', self.target_ip)}. "
                    f"Run without --keywords-saved once to create one."
                )
                return []
            return loaded

        return kwmod.interactive_keyword_menu('smb', self.target_ip, self.logger)

    def create_output_structure(self):
        """Create output directory structure"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(f"{self.output_dir}/by_type", exist_ok=True)
            os.makedirs(f"{self.output_dir}/by_share", exist_ok=True)
            self.logger.info(f"Output directory: {self.output_dir}/")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create output structure: {e}")
            return False

    def connect_smb(self):
        """Connect to SMB server"""
        try:
            self.logger.info("Connecting to SMB server...")
            import getpass
            password = getpass.getpass(f"Enter password for {self.credentials['username']}: ")

            self.smb_conn = SMBConnection(self.target_ip, self.target_ip, timeout=30)
            result = self.smb_conn.login(self.credentials['username'], password,
                                         self.credentials['domain'])
            if result:
                self.logger.info("SMB connection established")
                return True
            else:
                self.logger.error("SMB authentication failed")
                return False

        except Exception as e:
            self.logger.error(f"SMB connection failed: {e}")
            return False

    def get_files_to_download(self):
        """Get list of files to download based on selected file types"""
        files_to_download = []

        for share_name, share_info in self.index_data['shares'].items():
            if not share_info.get('accessible', False):
                continue

            for file_info in share_info.get('files', []):
                if not file_info.get('accessible', False):
                    continue

                file_ext = file_info.get('extension', '')
                if self.selected_filetypes and file_ext not in self.selected_filetypes:
                    continue

                file_size = file_info.get('size', 0)
                if file_size > self.max_filesize:
                    self.skipped_files.append({
                        'path': file_info['path'],
                        'size': file_size,
                        'reason': f'Size exceeds {self.format_size(self.max_filesize)} limit'
                    })
                    continue

                files_to_download.append(file_info)

        return files_to_download

    def download_file(self, file_info, output_path):
        """Download a single file from SMB"""
        try:
            smb_path = file_info['path']
            path_parts = smb_path.split('\\')
            share_name = path_parts[3]
            file_path = '\\'.join(path_parts[4:])

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, 'wb') as f:
                self.smb_conn.getFile(share_name, file_path, f.write)

            sha256_hash = hashlib.sha256()
            with open(output_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)

            return sha256_hash.hexdigest()

        except Exception as e:
            self.logger.error(f"Failed to download {file_info['path']}: {e}")
            return None

    def search_keywords_in_file(self, file_path, file_info):
        """Search for keywords in a downloaded file"""
        matches = []

        try:
            file_ext = file_info.get('extension', '').lower()

            if file_ext in RICH_DOC_EXTENSIONS:
                # Use Tika for rich document formats
                matches = self.search_with_tika(file_path)

            elif file_ext in ['txt', 'ini', 'cfg', 'conf', 'log', 'xml', 'json',
                               'yaml', 'yml', 'properties', 'env', 'sql', 'csv',
                               'py', 'sh', 'bat', 'ps1', 'js', 'php', 'rb',
                               'bak', 'old', 'backup', 'config', 'toml']:
                matches = self.search_text_file(file_path)

            elif file_ext in ['exe', 'dll', 'msi', 'bin']:
                matches = self.search_binary_file(file_path)

            elif file_ext in ['zip', '7z', 'rar', 'tar', 'gz', 'bz2']:
                matches = self.search_archive_file(file_path, file_ext)

            else:
                # Try as text file by default
                matches = self.search_text_file(file_path)

        except Exception as e:
            self.logger.debug(f"Error searching {file_path}: {e}")

        return matches

    def search_with_tika(self, file_path):
        """Extract text via Tika and search for keywords"""
        matches = []

        text = extract_text(file_path, self.logger)
        if not text:
            return matches

        lines = text.splitlines()
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            line_lower = line_stripped.lower()

            for keyword in self.keywords:
                if keyword in line_lower:
                    positions = []
                    start = 0
                    while True:
                        pos = line_lower.find(keyword, start)
                        if pos == -1:
                            break
                        positions.append(pos)
                        start = pos + 1

                    if positions:
                        context_before = lines[line_num - 2].strip() if line_num > 1 else ""
                        context_after = lines[line_num].strip() if line_num < len(lines) else ""
                        matches.append({
                            'line_number': line_num,
                            'line_content': line_stripped,
                            'matched_keyword': keyword,
                            'context_before': context_before,
                            'context_after': context_after,
                            'keyword_positions': positions,
                            'source_type': 'tika_extracted'
                        })

        return matches

    def search_text_file(self, file_path):
        """Search keywords in plain text file"""
        matches = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()

                for keyword in self.keywords:
                    if keyword in line_lower:
                        positions = []
                        start = 0
                        while True:
                            pos = line_lower.find(keyword, start)
                            if pos == -1:
                                break
                            positions.append(pos)
                            start = pos + 1

                        if positions:
                            context_before = lines[line_num - 2].strip() if line_num > 1 else ""
                            context_after = lines[line_num].strip() if line_num < len(lines) else ""
                            matches.append({
                                'line_number': line_num,
                                'line_content': line.strip(),
                                'matched_keyword': keyword,
                                'context_before': context_before,
                                'context_after': context_after,
                                'keyword_positions': positions
                            })

        except Exception as e:
            self.logger.debug(f"Error reading text file {file_path}: {e}")

        return matches

    def search_binary_file(self, file_path):
        """Search keywords in binary file using strings extraction"""
        matches = []

        try:
            result = subprocess.run(
                ['strings', '-a', '-n', '8', file_path],
                capture_output=True, text=True, timeout=60
            )

            if result.returncode == 0:
                strings_list = result.stdout.split('\n')

                for string_num, string_line in enumerate(strings_list, 1):
                    string_lower = string_line.lower()

                    for keyword in self.keywords:
                        if keyword in string_lower:
                            positions = []
                            start = 0
                            while True:
                                pos = string_lower.find(keyword, start)
                                if pos == -1:
                                    break
                                positions.append(pos)
                                start = pos + 1

                            if positions:
                                matches.append({
                                    'line_number': string_num,
                                    'line_content': string_line.strip(),
                                    'matched_keyword': keyword,
                                    'context_before': '[Binary string extraction]',
                                    'context_after': '',
                                    'keyword_positions': positions,
                                    'source_type': 'binary_strings'
                                })

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Strings extraction timeout for {file_path}")
        except FileNotFoundError:
            self.logger.warning("'strings' command not found. Install binutils package.")
        except Exception as e:
            self.logger.debug(f"Error extracting strings from {file_path}: {e}")

        return matches

    def search_archive_file(self, file_path, file_ext):
        """Search keywords in archive file"""
        matches = []
        file_size = os.path.getsize(file_path)

        if file_size > 10 * 1024 * 1024:
            self.logger.info(f"Archive too large to extract: {file_path}")
            return matches

        try:
            if file_ext == 'zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        zip_ref.extractall(temp_dir)

                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                extracted_path = os.path.join(root, file)
                                ext = Path(file).suffix.lower().lstrip('.')
                                try:
                                    if ext in RICH_DOC_EXTENSIONS:
                                        file_matches = self.search_with_tika(extracted_path)
                                    else:
                                        file_matches = self.search_text_file(extracted_path)
                                    for match in file_matches:
                                        match['source_type'] = 'archive_extracted'
                                        match['extracted_file'] = file
                                    matches.extend(file_matches)
                                except Exception as e:
                                    self.logger.debug(f"Error searching extracted file {file}: {e}")

        except Exception as e:
            self.logger.debug(f"Error processing archive {file_path}: {e}")

        return matches

    def highlight_keywords(self, line, keywords):
        """Generate keyword highlighting string"""
        line_lower = line.lower()
        highlight = [' '] * len(line)

        for keyword in keywords:
            keyword_lower = keyword.lower()
            start = 0
            while True:
                pos = line_lower.find(keyword_lower, start)
                if pos == -1:
                    break
                for i in range(pos, pos + len(keyword)):
                    if i < len(highlight):
                        highlight[i] = '^'
                start = pos + 1

        return ''.join(highlight).rstrip()

    def generate_results_file(self, file_type, matches_by_file):
        """Generate RESULTS.txt for a file type"""
        results_file = f"{self.output_dir}/by_type/{file_type}/RESULTS.txt"
        os.makedirs(os.path.dirname(results_file), exist_ok=True)

        with open(results_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("Tango Keyword Search Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"File Type:      .{file_type}\n")
            f.write(f"Target:         {self.target_ip}\n")
            f.write(f"Scan Date:      {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

            total_files = len(matches_by_file)
            files_with_matches = len([f for f, m in matches_by_file.items() if m])
            total_matches = sum(len(matches) for matches in matches_by_file.values())

            f.write(f"Files Scanned:  {total_files}\n")
            f.write(f"Files Matched:  {files_with_matches}\n")
            f.write(f"Total Matches:  {total_matches}\n")

            if file_type in RICH_DOC_EXTENSIONS:
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
                file_info = None
                for df in self.downloaded_files:
                    if df['local_path'].endswith(os.path.basename(file_path)):
                        file_info = df
                        break

                if file_info:
                    f.write(f"FILE: {file_info['smb_path']}\n")
                    f.write(f"LOCAL PATH: {file_info['local_path']}\n")
                    f.write(f"SIZE: {self.format_size(file_info['size'])} ({file_info['size']:,} bytes)\n")
                    if file_info.get('modified'):
                        f.write(f"MODIFIED: {file_info['modified'][:19]}\n")
                else:
                    f.write(f"FILE: {file_path}\n")

                matched_keywords = list(set(match['matched_keyword'] for match in matches))
                f.write(f"MATCHES: {len(matches)} (keywords: {', '.join(matched_keywords)})\n")
                f.write("#" * 80 + "\n\n")

                for i, match in enumerate(matches, 1):
                    f.write(f"[Match #{i} - Line {match['line_number']}]\n")
                    if match['context_before']:
                        f.write(f"{match['line_number']-1}: {match['context_before']}\n")
                    f.write(f"{match['line_number']}: {match['line_content']}\n")
                    highlight_str = self.highlight_keywords(match['line_content'], [match['matched_keyword']])
                    if highlight_str.strip():
                        f.write(f"{' ' * len(str(match['line_number']))}: {highlight_str}\n")
                    if match['context_after']:
                        f.write(f"{match['line_number']+1}: {match['context_after']}\n")
                    f.write("\n")

                f.write("-" * 80 + "\n")
                f.write("SUMMARY FOR THIS FILE:\n")

                password_matches = [m for m in matches if 'pass' in m['matched_keyword']]
                admin_matches = [m for m in matches if 'admin' in m['matched_keyword']]
                key_matches = [m for m in matches if 'key' in m['matched_keyword']]

                if password_matches:
                    f.write(f"  Potential Credentials: {len(password_matches)} password fields found\n")
                if admin_matches:
                    f.write(f"  Admin Accounts: {len(admin_matches)} admin references\n")
                if key_matches:
                    f.write(f"  API Keys: {len(key_matches)} key references found\n")

                if password_matches or key_matches:
                    f.write("  Recommendation: HIGH PRIORITY - Contains potential credentials\n")
                elif admin_matches:
                    f.write("  Recommendation: MEDIUM PRIORITY - Contains admin references\n")
                else:
                    f.write("  Recommendation: LOW PRIORITY - Contains keyword matches\n")

                f.write("-" * 80 + "\n\n")

            if files_with_matches > 1:
                f.write("=" * 80 + "\n")
                f.write("OVERALL SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Files with Findings: {files_with_matches}\n")
                f.write(f"Total Matches: {total_matches}\n\n")
                f.write("Recommended Actions:\n")
                f.write("  1. Review all HIGH PRIORITY findings immediately\n")
                f.write("  2. Rotate any credentials found\n")
                f.write("  3. Audit configuration files for similar patterns\n\n")

            f.write("=" * 80 + "\n")
            f.write("End of Results\n")
            f.write("=" * 80 + "\n")
            f.write("Generated by Tango v1.1.0\n")
            f.write(f"Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

        return results_file

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

    def talk(self):
        """Main SMB talk phase execution"""
        try:
            if not self.load_index():
                return False

            self.selected_filetypes = self.interactive_filetype_selection()
            if not self.selected_filetypes:
                self.logger.info("No file types selected. Exiting.")
                return False

            self.keywords = self.interactive_keyword_input()
            if not self.keywords:
                self.logger.info("No keywords provided. Exiting.")
                return False

            if not self.create_output_structure():
                return False

            if not self.connect_smb():
                return False

            files_to_download = self.get_files_to_download()
            if not files_to_download:
                self.logger.info("No files to download with current selection.")
                return False

            self.logger.info("=" * 60)
            self.logger.info("[DOWNLOAD] Starting download and analysis")
            self.logger.info("=" * 60)
            self.logger.info(f"File types selected: {', '.join(self.selected_filetypes)}")
            self.logger.info(f"Total files: {len(files_to_download)}")
            self.logger.info(f"Size limit: {self.format_size(self.max_filesize)} per file")
            self.logger.info(f"Keywords: {len(self.keywords)} keywords loaded")

            tika_types = [t for t in self.selected_filetypes if t in RICH_DOC_EXTENSIONS]
            if tika_types:
                self.logger.info(f"Tika extraction: {', '.join(tika_types)}")

            files_by_type = defaultdict(list)
            for file_info in files_to_download:
                file_ext = file_info.get('extension', '')
                files_by_type[file_ext].append(file_info)

            for file_type, files in files_by_type.items():
                self.logger.info("=" * 60)
                self.logger.info(f"[DOWNLOAD] Processing .{file_type} ({len(files)} files)")
                self.logger.info("=" * 60)

                type_dir = f"{self.output_dir}/by_type/{file_type}"
                os.makedirs(type_dir, exist_ok=True)

                matches_by_file = {}

                for i, file_info in enumerate(files, 1):
                    file_basename = os.path.basename(file_info['path'].split('\\')[-1])
                    local_path = f"{type_dir}/{file_basename}"

                    self.logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] Downloading: {file_info['path']} ({self.format_size(file_info['size'])})")

                    sha256 = self.download_file(file_info, local_path)
                    if sha256:
                        self.logger.info(f"Downloaded: {local_path}")

                        download_record = {
                            'local_path': local_path,
                            'smb_path': file_info['path'],
                            'size': file_info['size'],
                            'extension': file_info['extension'],
                            'downloaded_at': datetime.now(timezone.utc).isoformat(),
                            'sha256': sha256,
                            'keywords_found': False,
                            'match_count': 0
                        }

                        matches = self.search_keywords_in_file(local_path, file_info)
                        matches_by_file[local_path] = matches

                        if matches:
                            download_record['keywords_found'] = True
                            download_record['match_count'] = len(matches)
                            self.download_stats['files_with_matches'] += 1
                            self.download_stats['matches_found'] += len(matches)
                            self.logger.match(f"{file_basename} ({len(matches)} matches)")

                        self.downloaded_files.append(download_record)
                        self.download_stats['downloaded_files'] += 1
                        self.download_stats['total_size'] += file_info['size']

                    if i % 10 == 0 or i == len(files):
                        progress_pct = (i / len(files)) * 100
                        self.logger.info(f"Progress: {i}/{len(files)} files ({progress_pct:.0f}%)")

                results_file = self.generate_results_file(file_type, matches_by_file)
                matches_found = sum(len(m) for m in matches_by_file.values())
                files_matched = len([f for f, m in matches_by_file.items() if m])
                self.logger.info(f"[RESULTS] .{file_type}: {matches_found} matches in {files_matched} files → {results_file}")

            duration = time.time() - self.start_time
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"

            self.logger.info("=" * 60)
            self.logger.info("[COMPLETE] Download & Analysis Finished")
            self.logger.info("=" * 60)
            self.logger.info(f"Duration: {duration_str}")
            self.logger.info(f"Files downloaded: {self.download_stats['downloaded_files']} ({len(self.skipped_files)} skipped)")
            self.logger.info(f"Total size: {self.format_size(self.download_stats['total_size'])}")
            self.logger.info(f"Keywords found: {self.download_stats['matches_found']} matches in {self.download_stats['files_with_matches']} files")

            self.logger.session_end(duration_str)
            return True

        except Exception as e:
            self.logger.critical(f"Talk phase failed: {e}")
            return False
        finally:
            if self.smb_conn:
                self.smb_conn.close()
