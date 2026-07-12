"""
Page Collector for Confluence

Collects page content, versions, metadata, and labels.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class PageCollector:
    """Collects page data from Confluence spaces."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize page collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})
        self.collectors_config = self.config.get("collectors", {})

    def collect_space_pages(self, space_key: str) -> Dict[str, Any]:
        """
        Collect all pages from a space.

        Args:
            space_key: Space key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Starting page collection for space: {space_key}")

        pages_data = {
            "space_key": space_key,
            "pages": [],
            "blogposts": [],
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Collect regular pages
        if self.collectors_config.get("pages", True):
            content_types = self.config.get("content_types", ["page", "blogpost"])

            for content_type in content_types:
                item_list = []
                for page in self.api.get_space_pages(space_key, content_type=content_type):
                    # Get full page content
                    full_page = self._collect_page_details(page, content_type)
                    item_list.append(full_page)

                    if content_type == "page":
                        pages_data["pages"].append(full_page)
                    else:
                        pages_data["blogposts"].append(full_page)

            # Save collected data
            output_path = f"{space_key}/pages.json"
            self.storage.save(
                pages_data,
                output_path,
                collection_type="space_pages",
                include_request_log=True,
                request_log=self.api.get_request_log()
            )

            logger.info(f"Saved {len(pages_data['pages'])} pages and {len(pages_data['blogposts'])} blogposts")

        return {
            "space_key": space_key,
            "pages_collected": len(pages_data["pages"]),
            "blogposts_collected": len(pages_data["blogposts"]),
            "status": "complete"
        }

    def _collect_page_details(
        self,
        page: Dict[str, Any],
        content_type: str
    ) -> Dict[str, Any]:
        """
        Collect detailed information for a single page.

        Args:
            page: Basic page data
            content_type: Type of content

        Returns:
            Full page details
        """
        page_id = page.get("id")

        page_details = {
            "basic_info": page,
            "content": None,
            "versions": [],
            "comments": [],
            "restrictions": {},
            "labels": [],
            "attachments": []
        }

        try:
            # Get full content (storage format)
            if self.collectors_config.get("metadata", True):
                full_page = self.api.get_page_by_id(
                    page_id,
                    expand="body.storage,version,metadata.labels"
                )
                if full_page:
                    page_details["basic_info"] = full_page

            # Get content body
            if self.collectors_config.get("metadata", True):
                content = self.api.get_all_page_content(page_id)
                page_details["content"] = content

            # Get version history
            if self.collectors_config.get("versions", True):
                versions = self.api.get_page_versions(page_id)
                page_details["versions"] = versions

            # Get comments
            if self.collectors_config.get("comments", True):
                comments = self.api.get_page_comments(page_id)
                page_details["comments"] = comments

            # Get restrictions
            if self.collectors_config.get("restrictions", True):
                read_restrictions = self.api.get_page_restrictions(page_id, "read")
                update_restrictions = self.api.get_page_restrictions(page_id, "update")
                page_details["restrictions"] = {
                    "read": read_restrictions,
                    "update": update_restrictions
                }

            # Get labels
            if self.collectors_config.get("labels", True):
                labels = self.api.get_page_labels(page_id)
                page_details["labels"] = labels

            # Get attachments
            if self.collectors_config.get("attachments", True):
                attachments = self.api.get_page_attachments(page_id)
                page_details["attachments"] = attachments

        except Exception as e:
            logger.error(f"Error collecting details for page {page_id}: {e}")
            page_details["_error"] = str(e)

        return page_details
