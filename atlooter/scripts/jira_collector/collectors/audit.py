"""
Audit Log Collector for Jira

Collects Jira audit log entries.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class AuditCollector:
    """Collects audit log data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize audit collector.

        Args:
            api_client: Jira API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_audit_log(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Collect Jira audit log entries.

        Args:
            date_from: Start date filter
            date_to: End date filter

        Returns:
            Collection summary
        """
        logger.info("Collecting Jira audit log")

        # Collect audit entries
        audit_entries = self.api.get_audit_log(
            date_from=date_from,
            date_to=date_to
        )

        audit_data = {
            "filters": {
                "date_from": date_from,
                "date_to": date_to
            },
            "entries": audit_entries,
            "summary": {
                "total_entries": len(audit_entries)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Save collected data
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
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
