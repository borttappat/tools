"""
Comment Collector for Jira

Collects issue comments and their metadata.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class CommentCollector:
    """Collects comment data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize comment collector.

        Args:
            api_client: Jira API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_issue_comments(
        self,
        issue_id: str
    ) -> Dict[str, Any]:
        """
        Collect all comments from a specific issue.

        Args:
            issue_id: Issue ID or key

        Returns:
            Collection summary
        """
        logger.info(f"Collecting comments for issue {issue_id}")

        comments = self.api.get_issue_comments(issue_id)

        comments_data = {
            "issue_id": issue_id,
            "comments": comments,
            "total_comments": len(comments),
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = f"comments/{issue_id}_comments.json"
        self.storage.save(
            comments_data,
            output_path,
            collection_type="issue_comments",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return {
            "issue_id": issue_id,
            "comments_collected": len(comments),
            "status": "complete"
        }

    def collect_project_comments(
        self,
        project_key: str
    ) -> Dict[str, Any]:
        """
        Collect comments from all issues in a project.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting all comments from project: {project_key}")

        # Get all issues in project
        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key")

        all_comments = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "total_issues": len(issues),
                "issues_with_comments": 0,
                "total_comments": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Collect comments for each issue
        for issue in issues:
            issue_key = issue.get("key")
            issue_id = issue.get("id")

            comments = self.api.get_issue_comments(issue_id)

            if comments:
                all_comments["issues"][issue_key] = {
                    "comments": comments,
                    "count": len(comments)
                }
                all_comments["summary"]["issues_with_comments"] += 1
                all_comments["summary"]["total_comments"] += len(comments)

        # Save collected data
        output_path = f"{project_key}/all_comments.json"
        self.storage.save(
            all_comments,
            output_path,
            collection_type="project_comments",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_comments["summary"]
