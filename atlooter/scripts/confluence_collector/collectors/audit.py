"""
Audit Log Collector for Confluence

Collects Confluence audit log entries.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from ..api_client import ForensicsConfluenceClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class AuditCollector:
    """Collects audit log data from Confluence."""

    def __init__(
        self,
        api_client: ForensicsConfluenceClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize audit collector.

        Args:
            api_client: Confluence API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_audit_log(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        space_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Collect audit log entries.

        Args:
            date_from: Start date filter (ISO format, e.g., "2024-01-01")
            date_to: End date filter (ISO format, e.g., "2024-12-31")
            space_key: Optional space filter

        Returns:
            Collection summary
        """
        logger.info("Collecting audit log")

        # Build filter parameters
        params = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        if space_key:
            params["space_key"] = space_key

        # Collect audit entries
        audit_entries = self.api.get_audit_log(
            date_from=date_from,
            date_to=date_to
        )

        audit_data = {
            "filters": params,
            "entries": audit_entries,
            "summary": {
                "total_entries": len(audit_entries)
            },
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        # Save collected data
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = f"audit/audit_log_{timestamp}.json"
        self.storage.save(
            audit_data,
            output_path,
            collection_type="audit_log",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(audit_entries)} audit entries")

        return audit_data["summary"]

    def collect_space_audit_log(
        self,
        space_key: str
    ) -> Dict[str, Any]:
        """
        Collect audit log entries for a specific space.

        Args:
            space_key: Space key to collect audit log for

        Returns:
            Collection summary
        """
        logger.info(f"Collecting audit log for space: {space_key}")

        return self.collect_audit_log(space_key=space_key)
