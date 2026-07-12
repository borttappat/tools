"""
Restriction Collector for Confluence

Collects page and space restriction/permission data.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class RestrictionCollector:
    """Collects restriction and permission data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize restriction collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_space_permissions(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect permissions for a specific space.

        Args:
            space_key: Space key to collect permissions for

        Returns:
            Collection summary
        """
        logger.info(f"Collecting permissions for space: {space_key}")

        permissions_data = {
            "space_key": space_key,
            "permissions": {},
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Get space-level permissions
            space_perms = self.api.get_space_permissions(space_key)
            permissions_data["permissions"]["space"] = space_perms

        except Exception as e:
            logger.error(f"Error getting space permissions: {e}")
            permissions_data["error"] = str(e)

        # Save collected data
        output_path = f"{space_key}/space_permissions.json"
        self.storage.save(
            permissions_data,
            output_path,
            collection_type="space_permissions",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return {
            "space_key": space_key,
            "status": "complete"
        }

    def collect_page_restrictions(
        self,
        space_key: str,
        page_id: str
    ) -> Dict[str, Any]:
        """
        Collect restrictions for a specific page.

        Args:
            space_key: Space key
            page_id: Page ID

        Returns:
            Collection summary
        """
        logger.info(f"Collecting restrictions for page {page_id}")

        restrictions_data = {
            "space_key": space_key,
            "page_id": page_id,
            "restrictions": {
                "read": None,
                "update": None
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Get read restrictions
            read_restrictions = self.api.get_page_restrictions(page_id, "read")
            restrictions_data["restrictions"]["read"] = read_restrictions

            # Get update restrictions
            update_restrictions = self.api.get_page_restrictions(page_id, "update")
            restrictions_data["restrictions"]["update"] = update_restrictions

        except Exception as e:
            logger.error(f"Error getting page restrictions: {e}")
            restrictions_data["error"] = str(e)

        # Save collected data
        output_path = f"{space_key}/restrictions/page_{page_id}_restrictions.json"
        self.storage.save(
            restrictions_data,
            output_path,
            collection_type="page_restrictions",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return {
            "page_id": page_id,
            "status": "complete"
        }

    def collect_all_space_restrictions(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect restrictions for all pages in a space.

        Args:
            space_key: Space key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting all restrictions for space: {space_key}")

        all_restrictions = {
            "space_key": space_key,
            "pages": {},
            "summary": {
                "total_pages": 0,
                "pages_with_restrictions": 0
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Get all pages
        page_ids = []
        for page in self.api.get_space_pages(space_key, content_type="page"):
            page_ids.append(page.get("id"))

        all_restrictions["summary"]["total_pages"] = len(page_ids)

        # Collect restrictions for each page
        for page_id in page_ids:
            read_restrictions = self.api.get_page_restrictions(page_id, "read")
            update_restrictions = self.api.get_page_restrictions(page_id, "update")

            if read_restrictions or update_restrictions:
                all_restrictions["pages"][page_id] = {
                    "read_restrictions": read_restrictions,
                    "update_restrictions": update_restrictions
                }
                all_restrictions["summary"]["pages_with_restrictions"] += 1

        # Save collected data
        output_path = f"{space_key}/all_restrictions.json"
        self.storage.save(
            all_restrictions,
            output_path,
            collection_type="all_space_restrictions",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_restrictions["summary"]
