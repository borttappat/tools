"""
Remote Link Collector for Jira

Collects remote/web links attached to issues (links to external resources,
Confluence pages, other tools, etc). Only stores issues that have remote links.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from tqdm import tqdm

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class RemoteLinkCollector:
    """Collects remote link data from Jira issues."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_project_remote_links(self, project_key: str) -> Dict[str, Any]:
        """
        Collect all remote links from issues in a project.
        Only stores issues that have remote links.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting remote links from project: {project_key}")

        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key")

        all_remote_links = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "total_issues_scanned": len(issues),
                "issues_with_remote_links": 0,
                "total_remote_links": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        for issue in tqdm(issues, desc="Checking remote links", unit=" issues"):
            issue_key = issue.get("key")
            remote_links = self.api.get_issue_remote_links(issue_key)

            if not remote_links:
                continue

            all_remote_links["issues"][issue_key] = {
                "remote_links": remote_links,
                "count": len(remote_links)
            }
            all_remote_links["summary"]["issues_with_remote_links"] += 1
            all_remote_links["summary"]["total_remote_links"] += len(remote_links)

        logger.info(
            f"  {all_remote_links['summary']['issues_with_remote_links']} issues with remote links, "
            f"{all_remote_links['summary']['total_remote_links']} total"
        )

        output_path = f"{project_key}/remote_links.json"
        self.storage.save(
            all_remote_links,
            output_path,
            collection_type="project_remote_links",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_remote_links["summary"]
