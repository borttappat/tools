"""
Tango Local Walk Phase
Indexes a local directory tree (e.g. a file server dump) without any authentication.
"""

import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from logger import create_logger


class LocalWalker:
    def __init__(self, root_path):
        self.root_path = Path(root_path).resolve()
        if not self.root_path.exists():
            raise ValueError(f"Path does not exist: {root_path}")
        if not self.root_path.is_dir():
            raise ValueError(f"Path is not a directory: {root_path}")

        self.name = self.root_path.name
        self.logger = create_logger(self.name, "local-walk")
        self.start_time = time.time()

        self.files = []
        self.file_types = defaultdict(lambda: {"count": 0, "total_size": 0})
        self.large_files = []

        self.total_files = 0
        self.total_size = 0
        self.empty_files = 0
        self.access_denied = []

    def walk(self):
        """Walk the local directory tree and build an index."""
        try:
            self.logger.info(f"Root path: {self.root_path}")
            self.logger.info("Scanning directory tree...")

            for root, dirs, files in os.walk(self.root_path):
                dirs.sort()
                files.sort()

                for filename in files:
                    file_path = Path(root) / filename

                    try:
                        stat = file_path.stat()
                        size = stat.st_size

                        if size == 0:
                            self.empty_files += 1
                            continue

                        extension = file_path.suffix.lower().lstrip('.')
                        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                        created = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()

                        file_info = {
                            'path': str(file_path),
                            'relative_path': str(file_path.relative_to(self.root_path)),
                            'size': size,
                            'extension': extension,
                            'modified': modified,
                            'created': created,
                        }

                        self.files.append(file_info)
                        self.total_files += 1
                        self.total_size += size

                        self.file_types[extension]["count"] += 1
                        self.file_types[extension]["total_size"] += size

                        if size > 50 * 1024 * 1024:
                            self.large_files.append(file_info)

                    except PermissionError:
                        self.access_denied.append(str(file_path))
                        self.logger.warning(f"Access denied: {file_path}")
                    except Exception as e:
                        self.logger.debug(f"Error processing {file_path}: {e}")

            self.logger.info("=" * 50)
            self.logger.info("Local Walk Complete")
            self.logger.info("=" * 50)
            self.logger.info(f"Total files indexed: {self.total_files:,}")
            self.logger.info(f"Empty files skipped: {self.empty_files:,}")
            self.logger.info(f"Total size: {self.format_size(self.total_size)}")
            if self.access_denied:
                self.logger.info(f"Access denied: {len(self.access_denied)} items")

            human_index = self.generate_human_readable_index()
            json_index = self.generate_json_index()

            self.logger.info(f"Index saved: {human_index}")
            self.logger.info(f"JSON saved: {json_index}")

            duration = time.time() - self.start_time
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"
            self.logger.session_end(duration_str)

            return True

        except Exception as e:
            self.logger.critical(f"Local walk failed: {e}")
            return False

    def generate_json_index(self):
        """Write machine-readable JSON index."""
        filename = f"local_index_{self.name}.json"

        data = {
            "metadata": {
                "type": "local",
                "root_path": str(self.root_path),
                "name": self.name,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "tango_version": "1.1.0"
            },
            "summary": {
                "total_files": self.total_files,
                "empty_files": self.empty_files,
                "total_size_bytes": self.total_size,
                "access_denied_count": len(self.access_denied),
                "unique_extensions": len(self.file_types)
            },
            "files": self.files,
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

    def generate_human_readable_index(self):
        """Write human-readable index report."""
        filename = f"local_index_{self.name}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("Tango Local Index Report\n")
            f.write("=" * 80 + "\n")
            f.write(f"Root Path:  {self.root_path}\n")
            f.write(f"Scan Date:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
            f.write(f"Files:      {self.total_files:,} indexed\n")
            f.write(f"Empty:      {self.empty_files:,} skipped (0 bytes)\n")
            f.write(f"Total Size: {self.format_size(self.total_size)}\n")
            if self.access_denied:
                f.write(f"Denied:     {len(self.access_denied)} items\n")
            f.write("\n")

            # File type summary
            f.write("=" * 80 + "\n")
            f.write("File Type Summary (sorted by count)\n")
            f.write("=" * 80 + "\n")

            sorted_types = sorted(self.file_types.items(), key=lambda x: x[1]["count"], reverse=True)
            for ext, info in sorted_types:
                ext_display = f".{ext}" if ext else "(no extension)"
                f.write(f"{ext_display:<12} {info['count']:>6} files    {self.format_size(info['total_size']):>10}\n")
            f.write(f"\nTotal: {self.total_files:,} files across {len(self.file_types)} file types\n")
            f.write(f"Empty files skipped: {self.empty_files:,}\n\n")

            # Large files
            if self.large_files:
                f.write("=" * 80 + "\n")
                f.write("Large Files (>50MB)\n")
                f.write("=" * 80 + "\n")
                for fi in self.large_files:
                    f.write(f"{fi['relative_path']}  ({self.format_size(fi['size'])})\n")
                f.write(f"\nTotal: {len(self.large_files)} large files\n\n")

            # Access denied
            if self.access_denied:
                f.write("=" * 80 + "\n")
                f.write("Access Denied\n")
                f.write("=" * 80 + "\n")
                for p in self.access_denied[:20]:
                    f.write(f"  - {p}\n")
                if len(self.access_denied) > 20:
                    f.write(f"  ... and {len(self.access_denied) - 20} more\n")
                f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("Next Steps:\n")
            f.write(f"  tango local-talk {self.root_path}\n")
            f.write(f"  tango local-talk {self.root_path} --filetypes pdf,docx,xlsx,txt\n")
            f.write("=" * 80 + "\n")

        return filename

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
