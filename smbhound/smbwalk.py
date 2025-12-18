"""
SMBHound Walk Phase Implementation
Indexes SMB shares and enumerates all files
"""

import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import stat

from impacket.smbconnection import SMBConnection
from impacket import smb3structs

from logger import create_logger

class SMBWalker:
    def __init__(self, target_ip, username, password, domain="WORKGROUP", dc_ip=None):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_ip = dc_ip
        
        self.logger = create_logger(target_ip, "walk")
        self.start_time = time.time()
        
        # Results storage
        self.shares = {}
        self.all_files = []
        self.file_types = defaultdict(lambda: {"count": 0, "total_size": 0})
        self.large_files = []  # Files > 50MB
        self.access_denied = {
            "shares": [],
            "directories": [],
            "files": []
        }
        
        # Statistics
        self.total_files = 0
        self.total_size = 0
        self.accessible_shares = 0
        self.denied_shares = 0
        
        # Connection
        self.smb_conn = None
    
    def connect(self):
        """Establish SMB connection"""
        try:
            self.logger.info(f"Connecting to \\\\{self.target_ip}...")
            
            # Create connection
            self.smb_conn = SMBConnection(self.target_ip, self.target_ip, timeout=30)
            
            # Login
            result = self.smb_conn.login(self.username, self.password, self.domain)
            
            if result:
                self.logger.info("Connection established")
                self.logger.info(f"Domain: {self.domain}")
                self.logger.info(f"User: {self.username}")
                return True
            else:
                self.logger.critical("Authentication failed")
                return False
                
        except Exception as e:
            self.logger.critical(f"Connection failed: {e}")
            return False
    
    def enumerate_shares(self):
        """Enumerate all shares on the target"""
        try:
            self.logger.info("Enumerating shares...")
            shares = self.smb_conn.listShares()
            
            share_names = []
            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Remove null terminator
                share_names.append(share_name)
            
            self.logger.info(f"Found {len(share_names)} shares: {', '.join(share_names)}")
            return share_names
            
        except Exception as e:
            self.logger.error(f"Failed to enumerate shares: {e}")
            return []
    
    def get_file_info(self, share_name, file_path, smb_file_obj=None):
        """Get file metadata"""
        try:
            # Get file attributes
            file_info = self.smb_conn.queryInfo(share_name, file_path)
            
            # Extract information
            size = file_info['FileStandardInformation']['EndOfFile']
            created = file_info['FileBasicInformation']['CreationTime']
            modified = file_info['FileBasicInformation']['LastWriteTime']
            
            # Convert times to ISO format
            created_iso = self.convert_time(created) if created else None
            modified_iso = self.convert_time(modified) if modified else None
            
            # Get file extension
            extension = Path(file_path).suffix.lower().lstrip('.')
            
            return {
                'path': f"\\\\{self.target_ip}\\{share_name}\\{file_path}",
                'size': size,
                'extension': extension,
                'modified': modified_iso,
                'created': created_iso,
                'accessible': True,
                'permissions': 'READ'
            }
            
        except Exception as e:
            self.logger.debug(f"queryInfo failed for {file_path}, using listPath metadata: {e}")
            
            # Fallback: use metadata from listPath SMB object
            if smb_file_obj:
                try:
                    size = smb_file_obj.get_filesize()
                    created_time = smb_file_obj.get_ctime_epoch()
                    modified_time = smb_file_obj.get_mtime_epoch()
                    
                    created_iso = datetime.fromtimestamp(created_time, tz=timezone.utc).isoformat() if created_time else None
                    modified_iso = datetime.fromtimestamp(modified_time, tz=timezone.utc).isoformat() if modified_time else None
                    
                    extension = Path(file_path).suffix.lower().lstrip('.')
                    
                    return {
                        'path': f"\\\\{self.target_ip}\\{share_name}\\{file_path}",
                        'size': size,
                        'extension': extension,
                        'modified': modified_iso,
                        'created': created_iso,
                        'accessible': True,
                        'permissions': 'READ'
                    }
                except Exception as fallback_error:
                    self.logger.debug(f"Fallback also failed for {file_path}: {fallback_error}")
            
            # If all else fails, mark as inaccessible
            return {
                'path': f"\\\\{self.target_ip}\\{share_name}\\{file_path}",
                'size': 0,
                'extension': Path(file_path).suffix.lower().lstrip('.'),
                'accessible': False,
                'reason': 'METADATA_UNAVAILABLE'
            }
    
    def convert_time(self, filetime):
        """Convert Windows FILETIME to ISO 8601 format"""
        try:
            # FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
            # Convert to Unix timestamp
            unix_timestamp = (filetime - 116444736000000000) / 10000000
            dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
            return dt.isoformat()
        except:
            return None
    
    def scan_directory(self, share_name, directory_path=""):
        """Recursively scan a directory"""
        files_found = []
        
        try:
            # List directory contents
            contents = self.smb_conn.listPath(share_name, directory_path + '*')
            
            for item in contents:
                filename = item.get_longname()
                
                # Skip current and parent directory entries
                if filename in ['.', '..']:
                    continue
                
                item_path = f"{directory_path}{filename}"
                
                # Check if it's a directory
                if item.is_directory():
                    self.logger.debug(f"Found subdirectory: {item_path}")
                    
                    # Recursively scan subdirectory
                    try:
                        subdir_files = self.scan_directory(share_name, f"{item_path}/")
                        files_found.extend(subdir_files)
                    except Exception as e:
                        self.logger.warning(f"Access denied: \\\\{self.target_ip}\\{share_name}\\{item_path}")
                        self.access_denied["directories"].append(f"\\\\{self.target_ip}\\{share_name}\\{item_path}")
                else:
                    # It's a file - pass the SMB object for fallback metadata
                    file_info = self.get_file_info(share_name, item_path, item)
                    files_found.append(file_info)
                    
                    if file_info['accessible']:
                        self.logger.debug(f"Found file: {item_path} ({file_info['size']} bytes)")
                        
                        # Update statistics
                        self.total_files += 1
                        self.total_size += file_info['size']
                        
                        # Track file types
                        ext = file_info['extension']
                        self.file_types[ext]["count"] += 1
                        self.file_types[ext]["total_size"] += file_info['size']
                        
                        # Track large files (>50MB)
                        if file_info['size'] > 50 * 1024 * 1024:
                            self.large_files.append(file_info)
                    else:
                        self.access_denied["files"].append(file_info['path'])
        
        except Exception as e:
            self.logger.error(f"Cannot scan directory {directory_path}: {e}")
        
        return files_found
    
    def scan_share(self, share_name):
        """Scan a single share"""
        self.logger.info(f"Processing share: {share_name}")
        
        try:
            # Try to connect to the share
            tree_id = self.smb_conn.connectTree(share_name)
            
            # If successful, mark as accessible
            self.accessible_shares += 1
            self.logger.info(f"{share_name}: Accessible (READ permissions)")
            
            # Scan the share
            files = self.scan_directory(share_name, "")
            
            # Disconnect from tree
            self.smb_conn.disconnectTree(tree_id)
            
            # Store share info
            self.shares[share_name] = {
                "accessible": True,
                "path": f"\\\\{self.target_ip}\\{share_name}",
                "permissions": "READ",
                "total_files": len([f for f in files if f['accessible']]),
                "total_size_bytes": sum(f['size'] for f in files if f['accessible']),
                "files": files
            }
            
            self.logger.info(f"{share_name}: {len(files)} files indexed")
            
        except Exception as e:
            # Share is not accessible
            self.denied_shares += 1
            self.logger.error(f"Cannot access share: {share_name} (ACCESS_DENIED)")
            self.access_denied["shares"].append(share_name)
            
            self.shares[share_name] = {
                "accessible": False,
                "path": f"\\\\{self.target_ip}\\{share_name}",
                "reason": "Insufficient privileges",
                "attempted_at": datetime.now(timezone.utc).isoformat()
            }
    
    def generate_human_readable_index(self):
        """Generate human-readable index file"""
        filename = f"smb_index_{self.target_ip}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("SMBHound Index Report\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:     {self.target_ip}\n")
            f.write(f"Scan Date:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"Domain:     {self.domain}\n")
            f.write(f"User:       {self.username}\n")
            f.write(f"Shares:     {len(self.shares)} found ({self.accessible_shares} accessible, {self.denied_shares} denied)\n")
            f.write(f"Files:      {self.total_files:,} indexed\n")
            f.write(f"Total Size: {self.format_size(self.total_size)}\n")
            f.write("\n")
            
            # Shares details
            for share_name, share_info in self.shares.items():
                f.write("=" * 80 + "\n")
                if share_info["accessible"]:
                    f.write(f"SHARE: {share_name} [ACCESSIBLE]\n")
                    f.write(f"Path: {share_info['path']}\n")
                    f.write(f"Permissions: {share_info['permissions']}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # File tree (simplified for now)
                    accessible_files = [f for f in share_info['files'] if f['accessible']]
                    for file_info in accessible_files[:10]:  # Show first 10 files
                        size_str = self.format_size(file_info['size'])
                        modified_str = file_info['modified'][:19] if file_info['modified'] else 'Unknown'
                        f.write(f"{file_info['path'].split('\\\\')[-1]} ({size_str}, Modified: {modified_str})\n")
                    
                    if len(accessible_files) > 10:
                        f.write(f"... and {len(accessible_files) - 10} more files\n")
                    
                else:
                    f.write(f"SHARE: {share_name} [ACCESS_DENIED]\n")
                    f.write(f"Path: {share_info['path']}\n")
                    f.write(f"Reason: {share_info['reason']}\n")
                    f.write("=" * 80 + "\n")
                
                f.write("\n")
            
            # File type summary
            f.write("=" * 80 + "\n")
            f.write("File Type Summary (sorted by count)\n")
            f.write("=" * 80 + "\n")
            
            # Sort file types by count
            sorted_types = sorted(self.file_types.items(), 
                                key=lambda x: x[1]["count"], reverse=True)
            
            for ext, info in sorted_types:
                ext_display = f".{ext}" if ext else "(no extension)"
                f.write(f"{ext_display:<12} {info['count']:>6} files    {self.format_size(info['total_size']):>10}\n")
            
            f.write(f"\nTotal: {self.total_files} files across {len(self.file_types)} file types\n\n")
            
            # Large files
            if self.large_files:
                f.write("=" * 80 + "\n")
                f.write("Large Files (>50MB) - Require Manual Review\n")
                f.write("=" * 80 + "\n")
                
                for file_info in self.large_files:
                    f.write(f"Path: {file_info['path']}\n")
                    f.write(f"Size: {self.format_size(file_info['size'])}\n")
                    f.write(f"Type: .{file_info['extension']}\n")
                    if file_info['modified']:
                        f.write(f"Modified: {file_info['modified'][:19]}\n")
                    f.write(f"Note: Large file - verify manually\n\n")
                
                f.write(f"[Total: {len(self.large_files)} large files logged]\n\n")
            
            # Access denied summary
            if any(self.access_denied.values()):
                f.write("=" * 80 + "\n")
                f.write("Access Denied Summary\n")
                f.write("=" * 80 + "\n")
                
                if self.access_denied["shares"]:
                    f.write(f"Shares with no access ({len(self.access_denied['shares'])}):\n")
                    for share in self.access_denied["shares"]:
                        f.write(f"  - {share}\n")
                    f.write("\n")
                
                if self.access_denied["directories"]:
                    f.write(f"Directories with no access ({len(self.access_denied['directories'])}):\n")
                    for directory in self.access_denied["directories"][:10]:
                        f.write(f"  - {directory}\n")
                    if len(self.access_denied["directories"]) > 10:
                        f.write(f"  ... and {len(self.access_denied['directories']) - 10} more\n")
                    f.write("\n")
                
                if self.access_denied["files"]:
                    f.write(f"Files with no access ({len(self.access_denied['files'])}):\n")
                    for file_path in self.access_denied["files"][:10]:
                        f.write(f"  - {file_path}\n")
                    if len(self.access_denied["files"]) > 10:
                        f.write(f"  ... and {len(self.access_denied['files']) - 10} more\n")
                    f.write("\n")
            
            # Footer
            f.write("=" * 80 + "\n")
            f.write("Index Generation Complete\n")
            f.write("=" * 80 + "\n")
            f.write(f"Index saved to: {filename}\n")
            f.write(f"Machine-readable index: smb_index_{self.target_ip}.json\n")
            if self.large_files:
                f.write(f"Large files report: large_files_{self.target_ip}.txt\n")
            f.write(f"Log file: {self.logger.log_filename}\n\n")
            f.write("Next Steps:\n")
            f.write("1. Review the file type summary above\n")
            f.write("2. Run 'smbhound talk' to begin analysis phase\n")
            f.write("3. Or specify file types: smbhound talk --filetypes txt,ini,xml\n")
        
        return filename
    
    def generate_json_index(self):
        """Generate machine-readable JSON index"""
        filename = f"smb_index_{self.target_ip}.json"
        
        # Collect all files for JSON
        all_files_list = []
        for share_info in self.shares.values():
            if share_info["accessible"]:
                all_files_list.extend(share_info["files"])
        
        data = {
            "metadata": {
                "target": self.target_ip,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "domain": self.domain,
                "username": self.username,
                "smbhound_version": "1.0.0"
            },
            "summary": {
                "total_shares": len(self.shares),
                "accessible_shares": self.accessible_shares,
                "denied_shares": self.denied_shares,
                "total_files": self.total_files,
                "total_size_bytes": self.total_size,
                "accessible_files": len([f for f in all_files_list if f['accessible']]),
                "denied_files": len([f for f in all_files_list if not f['accessible']])
            },
            "shares": self.shares,
            "file_types": {
                ext: {
                    "count": info["count"],
                    "total_size": info["total_size"],
                    "average_size": info["total_size"] // info["count"] if info["count"] > 0 else 0
                }
                for ext, info in self.file_types.items()
            },
            "large_files": self.large_files,
            "access_denied": self.access_denied
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def generate_large_files_report(self):
        """Generate large files report"""
        if not self.large_files:
            return None
        
        filename = f"large_files_{self.target_ip}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SMBHound Large Files Report (>50MB)\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"Scan Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Large Files: {len(self.large_files)}\n")
            total_large_size = sum(f['size'] for f in self.large_files)
            f.write(f"Combined Size: {self.format_size(total_large_size)}\n\n")
            f.write("These files require manual review or specialized tools for analysis.\n\n")
            
            for i, file_info in enumerate(self.large_files, 1):
                f.write("=" * 80 + "\n")
                f.write(f"File #{i}\n")
                f.write("=" * 80 + "\n")
                f.write(f"Path: {file_info['path']}\n")
                f.write(f"Size: {self.format_size(file_info['size'])} ({file_info['size']:,} bytes)\n")
                f.write(f"Type: .{file_info['extension']}\n")
                if file_info['modified']:
                    f.write(f"Modified: {file_info['modified'][:19]}\n")
                if file_info['created']:
                    f.write(f"Created: {file_info['created'][:19]}\n")
                f.write("\nAnalysis Notes:\n")
                f.write(f"- Extension suggests {self.get_file_type_description(file_info['extension'])}\n")
                f.write("- Recommend: Manual review or specialized tools\n")
                f.write("- Consider downloading for offline analysis if permitted\n\n")
        
        return filename
    
    def get_file_type_description(self, extension):
        """Get description for file type"""
        descriptions = {
            'bak': 'backup file',
            'db': 'database file',
            'msi': 'installer package',
            'exe': 'executable file',
            'zip': 'archive file',
            '7z': 'archive file',
            'rar': 'archive file',
            'iso': 'disk image',
            'vhd': 'virtual disk',
            'vmdk': 'virtual disk'
        }
        return descriptions.get(extension, f'{extension} file')
    
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
    
    def walk(self):
        """Main walk phase execution"""
        try:
            # Connect to SMB server
            if not self.connect():
                return False
            
            # Enumerate shares
            share_names = self.enumerate_shares()
            if not share_names:
                self.logger.error("No shares found")
                return False
            
            # Scan each share
            for share_name in share_names:
                self.scan_share(share_name)
            
            # Generate reports
            self.logger.info("=" * 50)
            self.logger.info("Walk Phase Complete")
            self.logger.info("=" * 50)
            self.logger.info(f"Total files indexed: {self.total_files:,}")
            self.logger.info(f"Total size: {self.format_size(self.total_size)}")
            self.logger.info(f"Accessible shares: {self.accessible_shares}")
            self.logger.info(f"Denied shares: {self.denied_shares}")
            
            # Generate output files
            human_index = self.generate_human_readable_index()
            json_index = self.generate_json_index()
            large_files_report = self.generate_large_files_report()
            
            self.logger.info(f"Index saved: {human_index}")
            self.logger.info(f"JSON saved: {json_index}")
            if large_files_report:
                self.logger.info(f"Large files report: {large_files_report}")
            
            # Log duration
            duration = time.time() - self.start_time
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"
            self.logger.session_end(duration_str)
            
            return True
            
        except Exception as e:
            self.logger.critical(f"Walk phase failed: {e}")
            return False
        finally:
            if self.smb_conn:
                self.smb_conn.close()
