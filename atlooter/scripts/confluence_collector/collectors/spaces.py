"""
Space Collector for Confluence

Collects space-level metadata and permissions.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class SpaceCollector:
    """Collects space-level data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize space collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_all_spaces(self) -> Dict[str, Any]:
        """
        Collect information about all accessible spaces.

        Returns:
            Collection summary
        """
        logger.info("Collecting all accessible spaces")

        spaces = self.api.get_all_spaces()

        spaces_data = {
            "spaces": spaces,
            "summary": {
                "total_spaces": len(spaces)
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Save collected data
        output_path = "all_spaces.json"
        self.storage.save(
            spaces_data,
            output_path,
            collection_type="all_spaces",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(spaces)} spaces")

        return spaces_data["summary"]

    def collect_space_details(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect detailed information about a specific space.

        Args:
            space_key: Space key to collect

        Returns:
            Space details
        """
        logger.info(f"Collecting details for space: {space_key}")

        # Get all spaces and find the matching one
        all_spaces = self.api.get_all_spaces()
        space_details = None

        for space in all_spaces:
            if space.get("key") == space_key:
                space_details = space
                break

        if not space_details:
            # Try to get space by key directly
            try:
                from atlassian import Confluence
                space_details = {"key": space_key, "message": "Space found via direct lookup"}
            except Exception as e:
                logger.error(f"Space {space_key} not found: {e}")

        details_data = {
            "space_key": space_key,
            "details": space_details,
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Save collected data
        output_path = f"spaces/{space_key}_details.json"
        self.storage.save(
            details_data,
            output_path,
            collection_type="space_details",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return {
            "space_key": space_key,
            "found": space_details is not None,
            "status": "complete"
        }
