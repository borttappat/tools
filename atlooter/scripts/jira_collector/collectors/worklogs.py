"""
Worklog Collector for Jira

Collects issue worklog entries.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class WorklogCollector:
    """Collects worklog data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize worklog collector.

        Args:
            api_client: Jira API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_issue_worklogs(
        self,
        issue_id: str
    ) -> Dict[str, Any]:
        """
        Collect all worklogs from a specific issue.

        Args:
            issue_id: Issue ID or key

        Returns:
            Collection summary
        """
        logger.info(f"Collecting worklogs for issue {issue_id}")

        worklogs = self.api.get_issue_worklogs(issue_id)

        worklogs_data = {
            "issue_id": issue_id,
            "worklogs": worklogs,
            "summary": {
                "total_worklogs": len(worklogs),
                "total_time_spent_seconds": sum(
                    w.get("timeSpentSeconds", 0) for w in worklogs
                )
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = f"worklogs/{issue_id}_worklogs.json"
        self.storage.save(
            worklogs_data,
            output_path,
            collection_type="issue_worklogs",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return worklogs_data["summary"]

    def collect_project_worklogs(
        self,
        project_key: str
    ) -> Dict[str, Any]:
        """
        Collect worklogs from all issues in a project.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting all worklogs from project: {project_key}")

        # Get all issues in project
        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key")

        all_worklogs = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "total_issues": len(issues),
                "issues_with_worklogs": 0,
                "total_worklogs": 0,
                "total_time_spent_seconds": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Collect worklogs for each issue
        for issue in issues:
            issue_id = issue.get("id")

            worklogs = self.api.get_issue_worklogs(issue_id)

            if worklogs:
                all_worklogs["issues"][issue.get("key")] = {
                    "worklogs": worklogs,
                    "count": len(worklogs)
                }
                all_worklogs["summary"]["issues_with_worklogs"] += 1
                all_worklogs["summary"]["total_worklogs"] += len(worklogs)
                all_worklogs["summary"]["total_time_spent_seconds"] += sum(
                    w.get("timeSpentSeconds", 0) for w in worklogs
                )

        # Save collected data
        output_path = f"{project_key}/all_worklogs.json"
        self.storage.save(
            all_worklogs,
            output_path,
            collection_type="project_worklogs",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_worklogs["summary"]
