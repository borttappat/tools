"""
Attachment Collector for Confluence

Collects page attachments and their version history.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class AttachmentCollector:
    """Collects attachment data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize attachment collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})
        self.download_attachments = config.get("download_files", True)

    def collect_page_attachments(
        self,
        space_key: str,
        page_id: str,
        download_files: bool = True
    ) -> Dict[str, Any]:
        """
        Collect all attachments from a specific page.

        Args:
            space_key: Space key
            page_id: Page ID
            download_files: Whether to download actual files

        Returns:
            Collection summary
        """
        logger.info(f"Collecting attachments for page {page_id}")

        attachments_data = {
            "space_key": space_key,
            "page_id": page_id,
            "attachments": [],
            "downloaded_files": [],
            "failed_downloads": [],
            "summary": {
                "total_attachments": 0,
                "downloaded_count": 0,
                "failed_count": 0
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Get attachments list
        attachments = self.api.get_page_attachments(page_id)
        attachments_data["attachments"] = attachments
        attachments_data["summary"]["total_attachments"] = len(attachments)

        # Download files if requested
        if download_files and self.download_attachments:
            output_dir = self.storage.ensure_directory(
                space_key, "attachments", f"page_{page_id}"
            )

            for attachment in attachments:
                attachment_id = attachment.get("id")
                filename = attachment.get("title")

                if attachment_id and filename:
                    result = self.api.download_attachment(
                        attachment_id=attachment_id,
                        page_id=page_id,
                        filename=filename,
                        output_dir=str(output_dir)
                    )

                    if result:
                        attachments_data["downloaded_files"].append({
                            "filename": filename,
                            "saved_as": result,
                            "attachment_id": attachment_id
                        })
                        attachments_data["summary"]["downloaded_count"] += 1
                    else:
                        attachments_data["failed_downloads"].append({
                            "filename": filename,
                            "attachment_id": attachment_id,
                            "error": "Download failed"
                        })
                        attachments_data["summary"]["failed_count"] += 1

        # Save collected data
        output_path = f"{space_key}/attachments/page_{page_id}_attachments.json"
        self.storage.save(
            attachments_data,
            output_path,
            collection_type="page_attachments",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return attachments_data["summary"]

    def collect_space_attachments(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect all attachments from all pages in a space.

        Args:
            space_key: Space key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting all attachments for space: {space_key}")

        all_attachments = {
            "space_key": space_key,
            "pages": {},
            "summary": {
                "total_pages": 0,
                "pages_with_attachments": 0,
                "total_attachments": 0,
                "downloaded_count": 0,
                "failed_count": 0
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Get all pages
        page_ids = []
        for page in self.api.get_space_pages(space_key, content_type="page"):
            page_ids.append(page.get("id"))

        all_attachments["summary"]["total_pages"] = len(page_ids)

        # Collect attachments for each page
        for page_id in page_ids:
            page_result = self.collect_page_attachments(
                space_key, page_id, download_files=True
            )

            if page_result.get("total_attachments", 0) > 0:
                all_attachments["pages"][page_id] = page_result
                all_attachments["summary"]["pages_with_attachments"] += 1
                all_attachments["summary"]["total_attachments"] += page_result.get(
                    "total_attachments", 0
                )
                all_attachments["summary"]["downloaded_count"] += page_result.get(
                    "downloaded_count", 0
                )
                all_attachments["summary"]["failed_count"] += page_result.get(
                    "failed_count", 0
                )

        # Save summary
        output_path = f"{space_key}/attachments/all_attachments_summary.json"
        self.storage.save(
            all_attachments,
            output_path,
            collection_type="space_attachments_summary",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_attachments["summary"]
