"""
Watcher Collector for Jira

Collects the watcher list for each issue in a project.
Only stores issues that have watchers.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from tqdm import tqdm

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class WatcherCollector:
    """Collects watcher data from Jira issues."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_project_watchers(self, project_key: str) -> Dict[str, Any]:
        """
        Collect watchers for all issues in a project.
        Only stores issues that have watchers.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting watchers from project: {project_key}")

        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key")

        all_watchers = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "total_issues_scanned": len(issues),
                "issues_with_watchers": 0,
                "total_watchers": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        for issue in tqdm(issues, desc="Checking watchers", unit=" issues"):
            issue_key = issue.get("key")
            watcher_data = self.api.get_issue_watchers(issue_key)

            watchers = watcher_data.get("watchers", [])
            watch_count = watcher_data.get("watchCount", 0)

            if not watchers and watch_count == 0:
                continue

            all_watchers["issues"][issue_key] = {
                "watch_count": watch_count,
                "is_watching": watcher_data.get("isWatching", False),
                "watchers": watchers
            }
            all_watchers["summary"]["issues_with_watchers"] += 1
            all_watchers["summary"]["total_watchers"] += watch_count

        logger.info(
            f"  {all_watchers['summary']['issues_with_watchers']} issues with watchers"
        )

        output_path = f"{project_key}/watchers.json"
        self.storage.save(
            all_watchers,
            output_path,
            collection_type="project_watchers",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_watchers["summary"]
