"""
SMBHound Talk Phase Implementation
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

class SMBTalker:
    def __init__(self, target_ip=None, filetypes=None, keywords_file=None, 
                 keywords_inline=None, override_filesize=None):
        # If target_ip not provided, try to detect from existing index
        if target_ip is None:
            target_ip = self.detect_target_from_index()
        
        self.target_ip = target_ip
        self.logger = create_logger(target_ip, "talk")
        self.start_time = time.time()
        
        # Configuration
        self.selected_filetypes = self.parse_filetypes(filetypes) if filetypes else None
        self.keywords = self.parse_keywords(keywords_file, keywords_inline)
        self.max_filesize = self.parse_filesize_limit(override_filesize)
        
        # Index data
        self.index_data = None
        self.credentials = None  # Will be loaded from index metadata
        
        # Results storage
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
        
        # Output directory
        self.output_dir = f"downloads_{self.target_ip}"
        
        # Connection
        self.smb_conn = None
    
    def detect_target_from_index(self):
        """Try to detect target IP from existing index files"""
        for file in os.listdir('.'):
            if file.startswith('smb_index_') and file.endswith('.json'):
                # Extract IP from filename
                target_ip = file.replace('smb_index_', '').replace('.json', '')
                return target_ip
        return None
    
    def parse_filetypes(self, filetypes_str):
        """Parse comma-separated file types"""
        if not filetypes_str:
            return None
        return [ft.strip().lower() for ft in filetypes_str.split(',')]
    
    def parse_keywords(self, keywords_file, keywords_inline):
        """Parse keywords from file or inline"""
        keywords = []
        
        # Default keywords
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
        
        if keywords_file:
            try:
                with open(keywords_file, 'r') as f:
                    file_keywords = [line.strip().lower() for line in f if line.strip()]
                keywords.extend(file_keywords)
            except FileNotFoundError:
                self.logger.error(f"Keywords file not found: {keywords_file}")
                keywords = default_keywords
        elif keywords_inline:
            inline_keywords = [kw.strip().lower() for kw in keywords_inline.split(',')]
            keywords.extend(inline_keywords)
        else:
            keywords = default_keywords
        
        # Remove duplicates while preserving order
        seen = set()
        unique_keywords = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                unique_keywords.append(kw)
        
        return unique_keywords
    
    def parse_filesize_limit(self, override_str):
        """Parse file size limit"""
        if not override_str:
            return 50 * 1024 * 1024  # 50MB default
        
        if override_str.lower() == 'unlimited':
            return float('inf')
        
        try:
            return int(override_str) * 1024 * 1024  # Convert MB to bytes
        except ValueError:
            self.logger.warning(f"Invalid filesize override: {override_str}. Using default 50MB.")
            return 50 * 1024 * 1024
    
    def load_index(self):
        """Load the index file"""
        index_file = f"smb_index_{self.target_ip}.json"
        
        if not os.path.exists(index_file):
            self.logger.critical(f"No index found for {self.target_ip}. Run 'smbhound walk' first.")
            return False
        
        try:
            with open(index_file, 'r') as f:
                self.index_data = json.load(f)
            
            # Extract credentials from metadata (for SMB connection)
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
        print("SMBHound Talk Phase - File Type Selection")
        print("=" * 80)
        print(f"Target: {self.target_ip}")
        print(f"Index loaded: smb_index_{self.target_ip}.json")
        
        # Get file type statistics from index
        file_types = self.index_data.get('file_types', {})
        
        if not file_types:
            self.logger.error("No file types found in index")
            return []
        
        print("\nAvailable file types (sorted by count):\n")
        
        # Sort by count
        sorted_types = sorted(file_types.items(), key=lambda x: x[1]['count'], reverse=True)
        
        type_options = {}
        for i, (ext, info) in enumerate(sorted_types, 1):
            ext_display = f".{ext}" if ext else "(no extension)"
            size_str = self.format_size(info['total_size'])
            
            # Add recommendations
            recommendations = []
            if ext in ['txt', 'ini', 'xml', 'cfg', 'conf']:
                recommendations.append("HIGH VALUE")
            elif ext in ['bak', 'old', 'backup']:
                recommendations.append("HIGH PRIORITY")
            elif ext in ['exe', 'msi', 'dll']:
                recommendations.append("REVIEW NEEDED")
            elif ext in ['db', 'sqlite', 'mdb']:
                recommendations.append("MANUAL REVIEW")
            
            rec_str = f" [{', '.join(recommendations)}]" if recommendations else ""
            
            print(f"{i:2}. {ext_display:<12} {info['count']:>6} files    {size_str:>10}{rec_str}")
            type_options[str(i)] = ext
        
        print(f"\nRecommendations:")
        print(f"  - Start with: txt, ini, xml, cfg (small, high-value)")
        print(f"  - Review later: bak, exe, msi (larger, may need manual analysis)")
        print(f"  - Manual only: db (too large for automated processing)")
        
        while True:
            try:
                selection = input(f"\nEnter selection (comma-separated numbers, 'all', or 'q' to quit): ").strip()
                
                if selection.lower() == 'q':
                    return []
                elif selection.lower() == 'all':
                    return list(file_types.keys())
                else:
                    # Parse number selection
                    selected_numbers = [s.strip() for s in selection.split(',')]
                    selected_types = []
                    
                    for num in selected_numbers:
                        if num in type_options:
                            selected_types.append(type_options[num])
                        else:
                            print(f"Invalid selection: {num}")
                            continue
                    
                    if selected_types:
                        # Show selection summary
                        print(f"\nYou selected:")
                        total_files = 0
                        total_size = 0
                        
                        for ext in selected_types:
                            info = file_types[ext]
                            print(f"  - .{ext} ({info['count']} files, {self.format_size(info['total_size'])})")
                            total_files += info['count']
                            total_size += info['total_size']
                        
                        print(f"\nTotal: {total_files} files, {self.format_size(total_size)}")
                        
                        # Check for large files warning
                        large_types = [ext for ext in selected_types if file_types[ext]['total_size'] > self.max_filesize]
                        if large_types:
                            print(f"\nWARNING: Some types include files >{self.format_size(self.max_filesize)}. Large files will be skipped.")
                            print("Use --override-filesize to include larger files.")
                        
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
        """Interactive keyword input if not specified"""
        if self.keywords:
            return self.keywords
        
        print("\n" + "=" * 80)
        print("Keyword Search Configuration")
        print("=" * 80)
        print("\nEnter keywords for sensitive information search.")
        print("Keywords are case-insensitive and match substrings.")
        print("\nExamples:")
        print("  - password, passwd, pwd, pass")
        print("  - secret, credential, api_key, token")
        print("  - username, user, admin, root")
        print("  - database, connection, connectionstring")
        
        print("\nOptions:")
        print("  1. Enter keywords manually (comma-separated)")
        print("  2. Load keywords from file (path)")
        print("  3. Use default keyword set (recommended)")
        
        while True:
            try:
                choice = input("\nYour choice [1/2/3]: ").strip()
                
                if choice == '1':
                    keywords_input = input("Enter keywords (comma-separated): ").strip()
                    if keywords_input:
                        keywords = [kw.strip().lower() for kw in keywords_input.split(',')]
                        return keywords
                
                elif choice == '2':
                    file_path = input("Enter keywords file path: ").strip()
                    try:
                        with open(file_path, 'r') as f:
                            keywords = [line.strip().lower() for line in f if line.strip()]
                        return keywords
                    except FileNotFoundError:
                        print(f"File not found: {file_path}")
                        continue
                
                elif choice == '3':
                    # Use default keywords (already set in constructor)
                    print("\nUsing default keywords:")
                    default_keywords = self.parse_keywords(None, None)
                    print("  " + ", ".join(default_keywords[:15]) + f" [+{len(default_keywords)-15} more]")
                    
                    additional = input("\nAdd additional keywords (comma-separated, or press Enter to continue): ").strip()
                    if additional:
                        extra_keywords = [kw.strip().lower() for kw in additional.split(',')]
                        default_keywords.extend(extra_keywords)
                    
                    print(f"\nFinal keyword list ({len(default_keywords)} keywords)")
                    confirm = input("Proceed with keyword search? [Y/n]: ").strip().lower()
                    if confirm in ['', 'y', 'yes']:
                        return default_keywords
                
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
                    
            except KeyboardInterrupt:
                print("\nAborted.")
                return []
            except Exception as e:
                print(f"Error: {e}")
                continue
    
    def create_output_structure(self):
        """Create output directory structure"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(f"{self.output_dir}/by_type", exist_ok=True)
            os.makedirs(f"{self.output_dir}/by_share", exist_ok=True)
            
            self.logger.info(f"Creating output directory: {self.output_dir}/")
            self.logger.info("Output structure: by_type/ and by_share/")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to create output structure: {e}")
            return False
    
    def connect_smb(self):
        """Connect to SMB server using credentials from index"""
        try:
            self.logger.info("Connecting to SMB server...")
            
            # We need to prompt for password since it's not stored in index
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
                
                # Check if file type is selected
                file_ext = file_info.get('extension', '')
                if self.selected_filetypes and file_ext not in self.selected_filetypes:
                    continue
                
                # Check file size
                file_size = file_info.get('size', 0)
                if file_size > self.max_filesize:
                    self.skipped_files.append({
                        'path': file_info['path'],
                        'size': file_size,
                        'reason': f'Size exceeds {self.format_size(self.max_filesize)} limit',
                        'recommendation': 'Download manually or use --override-filesize'
                    })
                    continue
                
                files_to_download.append(file_info)
        
        return files_to_download
    
    def download_file(self, file_info, output_path):
        """Download a single file from SMB"""
        try:
            # Parse SMB path
            smb_path = file_info['path']
            path_parts = smb_path.split('\\')
            share_name = path_parts[3]  # \\server\share\path
            file_path = '\\'.join(path_parts[4:])
            
            # Create output directory
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Download file
            with open(output_path, 'wb') as f:
                self.smb_conn.getFile(share_name, file_path, f.write)
            
            # Calculate SHA256
            sha256_hash = hashlib.sha256()
            with open(output_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Failed to download {file_info['path']}: {e}")
            return None
    
    def search_keywords_in_file(self, file_path, file_info):
        """Search for keywords in a file"""
        matches = []
        
        try:
            # Determine file type and processing method
            file_ext = file_info.get('extension', '').lower()
            
            if file_ext in ['txt', 'ini', 'cfg', 'conf', 'log', 'xml', 'json', 'yaml', 'yml']:
                # Text files - direct search
                matches = self.search_text_file(file_path)
            
            elif file_ext in ['exe', 'dll', 'msi', 'bin']:
                # Binary files - extract strings
                matches = self.search_binary_file(file_path)
            
            elif file_ext in ['zip', '7z', 'rar', 'tar', 'gz', 'bz2']:
                # Archive files
                matches = self.search_archive_file(file_path, file_ext)
            
            else:
                # Try as text file by default
                matches = self.search_text_file(file_path)
        
        except Exception as e:
            self.logger.debug(f"Error searching {file_path}: {e}")
        
        return matches
    
    def search_text_file(self, file_path):
        """Search keywords in text file"""
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()
                
                for keyword in self.keywords:
                    if keyword in line_lower:
                        # Find all positions of the keyword
                        positions = []
                        start = 0
                        while True:
                            pos = line_lower.find(keyword, start)
                            if pos == -1:
                                break
                            positions.append(pos)
                            start = pos + 1
                        
                        if positions:
                            # Get context
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
            # Use strings command to extract printable strings
            result = subprocess.run(
                ['strings', '-a', '-n', '8', file_path],
                capture_output=True,
                text=True,
                timeout=60
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
        
        # Only extract small archives (<10MB)
        if file_size > 10 * 1024 * 1024:
            self.logger.info(f"Archive too large to extract: {file_path}")
            return matches
        
        try:
            if file_ext in ['zip']:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        zip_ref.extractall(temp_dir)
                        
                        # Search extracted files
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                extracted_path = os.path.join(root, file)
                                try:
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
                # Mark matched positions
                for i in range(pos, pos + len(keyword)):
                    if i < len(highlight):
                        highlight[i] = '^'
                start = pos + 1
        
        return ''.join(highlight).rstrip()
    
    def generate_results_file(self, file_type, matches_by_file):
        """Generate RESULTS.txt file for a file type"""
        results_file = f"{self.output_dir}/by_type/{file_type}/RESULTS.txt"
        
        # Create directory
        os.makedirs(os.path.dirname(results_file), exist_ok=True)
        
        with open(results_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("SMBHound Keyword Search Results\n")
            f.write("=" * 80 + "\n")
            f.write(f"File Type:      .{file_type}\n")
            f.write(f"Target:         {self.target_ip}\n")
            f.write(f"Scan Date:      {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            
            total_files = len(matches_by_file)
            files_with_matches = len([f for f, m in matches_by_file.items() if m])
            total_matches = sum(len(matches) for matches in matches_by_file.values())
            
            f.write(f"Files Scanned:  {total_files}\n")
            f.write(f"Files Matched:  {files_with_matches}\n")
            f.write(f"Total Matches:  {total_matches}\n\n")
            
            f.write(f"Keywords Used ({len(self.keywords)}):\n")
            # Format keywords in lines of ~70 chars
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
            
            # Results for each file
            for file_path, matches in matches_by_file.items():
                if not matches:
                    continue
                
                # File header
                f.write("#" * 80 + "\n")
                # Get file info from downloaded files
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
                    if file_info.get('created'):
                        f.write(f"CREATED: {file_info['created'][:19]}\n")
                else:
                    f.write(f"FILE: {file_path}\n")
                
                matched_keywords = list(set(match['matched_keyword'] for match in matches))
                f.write(f"MATCHES: {len(matches)} (keywords: {', '.join(matched_keywords)})\n")
                f.write("#" * 80 + "\n\n")
                
                # Show each match
                for i, match in enumerate(matches, 1):
                    f.write(f"[Match #{i} - Line {match['line_number']}]\n")
                    
                    # Context
                    if match['context_before']:
                        f.write(f"{match['line_number']-1}: {match['context_before']}\n")
                    
                    # Main line with highlighting
                    f.write(f"{match['line_number']}: {match['line_content']}\n")
                    
                    # Highlight matched keywords
                    highlight_str = self.highlight_keywords(match['line_content'], [match['matched_keyword']])
                    if highlight_str.strip():
                        f.write(f"{' ' * len(str(match['line_number']))}: {highlight_str}\n")
                    
                    # Context after
                    if match['context_after']:
                        f.write(f"{match['line_number']+1}: {match['context_after']}\n")
                    
                    f.write("\n")
                
                # File summary
                f.write("-" * 80 + "\n")
                f.write("SUMMARY FOR THIS FILE:\n")
                
                # Categorize findings
                password_matches = [m for m in matches if 'pass' in m['matched_keyword']]
                admin_matches = [m for m in matches if 'admin' in m['matched_keyword']]
                key_matches = [m for m in matches if 'key' in m['matched_keyword']]
                
                if password_matches:
                    f.write(f"  Potential Credentials: {len(password_matches)} password fields found\n")
                if admin_matches:
                    f.write(f"  Admin Accounts: {len(admin_matches)} admin references\n")
                if key_matches:
                    f.write(f"  API Keys: {len(key_matches)} key references found\n")
                
                # Risk assessment
                if password_matches or key_matches:
                    f.write("  Recommendation: HIGH PRIORITY - Contains potential credentials\n")
                elif admin_matches:
                    f.write("  Recommendation: MEDIUM PRIORITY - Contains admin references\n")
                else:
                    f.write("  Recommendation: LOW PRIORITY - Contains keyword matches\n")
                
                f.write("-" * 80 + "\n\n")
            
            # Overall summary if multiple files
            if files_with_matches > 1:
                f.write("=" * 80 + "\n")
                f.write("OVERALL SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Files with Findings: {files_with_matches}\n")
                f.write(f"Total Matches: {total_matches}\n\n")
                
                f.write("Recommended Actions:\n")
                f.write("  1. Review all HIGH PRIORITY findings immediately\n")
                f.write("  2. Rotate any credentials found\n")
                f.write("  3. Audit configuration files for similar patterns\n")
                f.write("  4. Implement secrets management solution\n\n")
            
            # Footer
            f.write("=" * 80 + "\n")
            f.write("End of Results\n")
            f.write("=" * 80 + "\n")
            f.write("Generated by SMBHound v1.0.0\n")
            f.write(f"Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        
        return results_file
    
    def format_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(size_bytes)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
    
    def talk(self):
        """Main talk phase execution"""
        try:
            # Load index
            if not self.load_index():
                return False
            
            # Interactive selections if not provided
            self.selected_filetypes = self.interactive_filetype_selection()
            if not self.selected_filetypes:
                self.logger.info("No file types selected. Exiting.")
                return False
            
            self.keywords = self.interactive_keyword_input()
            if not self.keywords:
                self.logger.info("No keywords provided. Exiting.")
                return False
            
            # Create output structure
            if not self.create_output_structure():
                return False
            
            # Connect to SMB
            if not self.connect_smb():
                return False
            
            # Get files to download
            files_to_download = self.get_files_to_download()
            
            if not files_to_download:
                self.logger.info("No files to download with current selection.")
                return False
            
            # Start download and analysis
            self.logger.info("=" * 60)
            self.logger.info("[DOWNLOAD] Starting download and analysis")
            self.logger.info("=" * 60)
            self.logger.info(f"File types selected: {', '.join(self.selected_filetypes)}")
            self.logger.info(f"Total files: {len(files_to_download)}")
            self.logger.info(f"Size limit: {self.format_size(self.max_filesize)} per file")
            self.logger.info(f"Keywords: {len(self.keywords)} keywords loaded")
            
            # Group files by type for processing
            files_by_type = defaultdict(list)
            for file_info in files_to_download:
                file_ext = file_info.get('extension', '')
                files_by_type[file_ext].append(file_info)
            
            # Process each file type
            for file_type, files in files_by_type.items():
                self.logger.info("=" * 60)
                self.logger.info(f"[DOWNLOAD] Processing file type: {file_type} ({len(files)} files)")
                self.logger.info("=" * 60)
                
                # Create type directory
                type_dir = f"{self.output_dir}/by_type/{file_type}"
                os.makedirs(type_dir, exist_ok=True)
                
                matches_by_file = {}
                
                # Download and analyze each file
                for i, file_info in enumerate(files, 1):
                    file_basename = os.path.basename(file_info['path'].split('\\')[-1])
                    local_path = f"{type_dir}/{file_basename}"
                    
                    # Download file
                    self.logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] Downloading: {file_info['path']} ({self.format_size(file_info['size'])})")
                    
                    sha256 = self.download_file(file_info, local_path)
                    if sha256:
                        self.logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] Downloaded: {local_path}")
                        
                        # Track downloaded file
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
                        
                        # Search for keywords
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
                    
                    # Progress update
                    if i % 10 == 0 or i == len(files):
                        progress_pct = (i / len(files)) * 100
                        size_downloaded = sum(f['size'] for f in self.downloaded_files[-i:])
                        self.logger.info(f"Progress: {i}/{len(files)} files ({progress_pct:.0f}%) | {self.format_size(size_downloaded)} downloaded")
                
                # Generate results file for this type
                results_file = self.generate_results_file(file_type, matches_by_file)
                matches_found = sum(len(matches) for matches in matches_by_file.values())
                files_with_matches = len([f for f, m in matches_by_file.items() if m])
                
                self.logger.info(f"[RESULTS] {file_type} files: {matches_found} matches found in {files_with_matches} files")
                self.logger.info(f"          Results saved to: {results_file}")
            
            # Generate final summary
            duration = time.time() - self.start_time
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"
            
            self.logger.info("=" * 60)
            self.logger.info("[COMPLETE] Download & Analysis Finished")
            self.logger.info("=" * 60)
            self.logger.info(f"Duration: {duration_str}")
            self.logger.info(f"Files downloaded: {self.download_stats['downloaded_files']} / {len(files_to_download)} ({len(self.skipped_files)} skipped)")
            self.logger.info(f"Total size downloaded: {self.format_size(self.download_stats['total_size'])}")
            self.logger.info(f"Keywords found: {self.download_stats['matches_found']} matches across {self.download_stats['files_with_matches']} files")
            
            self.logger.session_end(duration_str)
            
            return True
            
        except Exception as e:
            self.logger.critical(f"Talk phase failed: {e}")
            return False
        finally:
            if self.smb_conn:
                self.smb_conn.close()