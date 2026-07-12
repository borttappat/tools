"""
Link Collector for Jira

Collects issue link data. Fetches link data inline with the issue list
to avoid extra API calls. Only stores issues that have links.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class LinkCollector:
    """Collects issue link data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_project_links(
        self,
        project_key: str
    ) -> Dict[str, Any]:
        """
        Collect all issue links from a project.
        Fetches issuelinks field inline with the issue list to avoid
        extra API calls. Only stores issues that have links.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting links from project: {project_key}")

        # Fetch issues with issuelinks field included - no extra API calls needed
        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key,issuelinks")

        all_links = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "total_issues_scanned": len(issues),
                "issues_with_links": 0,
                "total_links": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        for issue in issues:
            issue_key = issue.get("key")
            links = issue.get("fields", {}).get("issuelinks", [])

            if not links:
                continue

            all_links["issues"][issue_key] = {
                "links": links,
                "count": len(links)
            }
            all_links["summary"]["issues_with_links"] += 1
            all_links["summary"]["total_links"] += len(links)

        logger.info(
            f"  {all_links['summary']['issues_with_links']} issues with links, "
            f"{all_links['summary']['total_links']} total"
        )

        output_path = f"{project_key}/all_links.json"
        self.storage.save(
            all_links,
            output_path,
            collection_type="project_links",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_links["summary"]
