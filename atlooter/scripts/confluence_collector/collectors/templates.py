"""
Template Collector for Confluence

Collects space and global templates.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class TemplateCollector:
    """Collects template data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize template collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_space_templates(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect all templates for a specific space.

        Args:
            space_key: Space key to collect templates from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting templates for space: {space_key}")

        templates_data = {
            "space_key": space_key,
            "templates": [],
            "summary": {
                "total_templates": 0
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        try:
            templates = self.api.get_templates(space_key)

            if templates:
                templates_data["templates"] = templates
                templates_data["summary"]["total_templates"] = len(templates)

        except Exception as e:
            logger.error(f"Error getting templates for {space_key}: {e}")
            templates_data["error"] = str(e)

        # Save collected data
        output_path = f"spaces/{space_key}/templates.json"
        self.storage.save(
            templates_data,
            output_path,
            collection_type="space_templates",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return templates_data["summary"]

    def collect_all_templates(self) -> Dict[str, Any]:
        """
        Collect all global and space templates.

        Returns:
            Collection summary
        """
        logger.info("Collecting all templates")

        all_templates = {
            "global_templates": [],
            "space_templates": {},
            "summary": {
                "total_global": 0,
                "total_by_space": {}
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Get global templates
            global_templates = self.api.get_templates()
            all_templates["global_templates"] = global_templates
            all_templates["summary"]["total_global"] = len(global_templates)

            # Get space templates for each space
            spaces = self.api.get_all_spaces()
            for space in spaces:
                space_key = space.get("key")
                try:
                    space_templates = self.api.get_templates(space_key)
                    if space_templates:
                        all_templates["space_templates"][space_key] = space_templates
                        all_templates["summary"]["total_by_space"][space_key] = len(space_templates)
                except Exception as e:
                    logger.warning(f"Could not get templates for space {space_key}: {e}")

        except Exception as e:
            logger.error(f"Error collecting templates: {e}")
            all_templates["error"] = str(e)

        # Save collected data
        output_path = "all_templates.json"
        self.storage.save(
            all_templates,
            output_path,
            collection_type="all_templates",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(
            f"Collected {all_templates['summary']['total_global']} global templates "
            f"and {len(all_templates['space_templates'])} space template sets"
        )

        return all_templates["summary"]
