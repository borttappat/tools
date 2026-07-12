"""
Data Storage Utilities for Jira Collector

Handles JSON/YAML output with forensic-grade metadata preservation.
"""

import os
import json
import yaml
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from pathlib import Path


class DataStorage:
    """
    Handles data persistence for forensic collections.

    Features:
    - JSON and YAML output formats
    - Automatic metadata injection (timestamp, collection info)
    - Nested directory creation
    - Request/response pairing
    """

    def __init__(
        self,
        base_dir: str,
        format: str = "json",
        include_metadata: bool = True
    ):
        """
        Initialize storage handler.

        Args:
            base_dir: Base directory for output
            format: Output format ('json' or 'yaml')
            include_metadata: Whether to add collection metadata
        """
        self.base_dir = Path(base_dir)
        self.format = format
        self.include_metadata = include_metadata
        self._collection_timestamp = datetime.now(timezone.utc).isoformat()

        # Ensure base directory exists
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _build_output_path(self, *path_parts: str) -> Path:
        """Build output path with automatic directory creation."""
        full_path = self.base_dir / os.path.join(*path_parts)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        return full_path

    def _wrap_with_metadata(self, data: Any, collection_type: str) -> Dict[str, Any]:
        """Wrap data with forensic metadata."""
        return {
            "_metadata": {
                "collection_timestamp": self._collection_timestamp,
                "collection_type": collection_type,
                "format": self.format,
                "tool_version": "1.0.0"
            },
            "_request_log": [],  # Populated later
            "data": data
        }

    def save(
        self,
        data: Any,
        path: str,
        collection_type: str = "general",
        include_request_log: bool = False,
        request_log: Optional[List[Dict]] = None
    ) -> Path:
        """
        Save data to file.

        Args:
            data: Data to save
            path: Relative path within base directory
            collection_type: Type of collection for metadata
            include_request_log: Whether to include request log
            request_log: Request log data if included

        Returns:
            Path to saved file
        """
        output_path = self._build_output_path(path)

        # Wrap with metadata if enabled
        if self.include_metadata:
            wrapped_data = self._wrap_with_metadata(data, collection_type)

            if include_request_log and request_log:
                wrapped_data["_request_log"] = request_log

            data_to_save = wrapped_data
        else:
            data_to_save = data

        # Save based on format
        if self.format == "json":
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False, default=str)
        elif self.format == "yaml":
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(data_to_save, f, default_flow_style=False, allow_unicode=True)
        else:
            raise ValueError(f"Unsupported format: {self.format}")

        return output_path

    def save_raw_response(
        self,
        response: Dict[str, Any],
        endpoint: str,
        request_id: str
    ) -> Path:
        """
        Save raw API response for forensic integrity.

        Args:
            response: Raw API response
            endpoint: API endpoint called
            request_id: Unique request identifier

        Returns:
            Path to saved file
        """
        path = f"raw_responses/{request_id}_{endpoint.replace('/', '_')}.json"
        return self.save(
            response,
            path,
            collection_type="raw_response",
            include_request_log=False
        )

    def save_collection_summary(
        self,
        summary: Dict[str, Any],
        collection_type: str
    ) -> Path:
        """
        Save collection summary report.

        Args:
            summary: Summary data
            collection_type: Type of collection

        Returns:
            Path to saved file
        """
        summary["_collected_at"] = datetime.now(timezone.utc).isoformat()
        return self.save(
            summary,
            f"summaries/{collection_type}_summary.json",
            collection_type="summary"
        )

    def ensure_directory(self, *path_parts: str) -> Path:
        """Ensure a directory exists within base dir."""
        path = self._build_output_path(*path_parts)
        path.mkdir(parents=True, exist_ok=True)
        return path
