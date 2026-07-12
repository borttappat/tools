"""
Comment Collector for Confluence

Collects page comments and their metadata.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class CommentCollector:
    """Collects comment data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize comment collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_page_comments(
        self,
        space_key: str,
        page_id: str
    ) -> Dict[str, Any]:
        """
        Collect all comments from a specific page.

        Args:
            space_key: Space key
            page_id: Page ID

        Returns:
            Collection summary
        """
        logger.info(f"Collecting comments for page {page_id}")

        comments = self.api.get_page_comments(page_id)

        comments_data = {
            "space_key": space_key,
            "page_id": page_id,
            "comments": comments,
            "total_comments": len(comments),
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        output_path = f"{space_key}/comments/page_{page_id}_comments.json"
        self.storage.save(
            comments_data,
            output_path,
            collection_type="page_comments",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return {
            "page_id": page_id,
            "comments_collected": len(comments),
            "status": "complete"
        }

    def collect_space_comments(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect comments from all pages in a space.

        Args:
            space_key: Space key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting comments for space: {space_key}")

        all_comments = {
            "space_key": space_key,
            "pages": {},
            "summary": {
                "total_pages": 0,
                "total_comments": 0,
                "pages_with_comments": 0
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Get all pages in space
        page_ids = []
        for page in self.api.get_space_pages(space_key, content_type="page"):
            page_ids.append(page.get("id"))

        all_comments["summary"]["total_pages"] = len(page_ids)

        # Collect comments for each page
        for page_id in page_ids:
            comments = self.api.get_page_comments(page_id)

            if comments:
                all_comments["pages"][page_id] = {
                    "comments": comments,
                    "count": len(comments)
                }
                all_comments["summary"]["pages_with_comments"] += 1
                all_comments["summary"]["total_comments"] += len(comments)

        # Save collected data
        output_path = f"{space_key}/all_comments.json"
        self.storage.save(
            all_comments,
            output_path,
            collection_type="space_comments",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_comments["summary"]
