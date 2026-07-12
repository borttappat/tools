"""
Issue Collector for Jira

Collects Jira issues with full field data, comments, and change history.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class IssueCollector:
    """Collects issue data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize issue collector.

        Args:
            api_client: Jira API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})
        self.collectors_config = self.config.get("collectors", {})

    def collect_project_issues(
        self,
        project_key: str,
        include_comments: bool = True,
        include_changelog: bool = True
    ) -> Dict[str, Any]:
        """
        Collect all issues from a project.

        Args:
            project_key: Project key to collect from
            include_comments: Whether to collect comments
            include_changelog: Whether to collect change history

        Returns:
            Collection summary
        """
        logger.info(f"Collecting issues from project: {project_key}")

        # Build JQL query
        jql = f"project = {project_key}"

        # Get all issues
        issues = self.api.get_issues_by_jql(
            jql=jql,
            fields="*",
            expand=None
        )

        collection_data = {
            "project_key": project_key,
            "issues": [],
            "summary": {
                "total_issues": len(issues),
                "issues_with_comments": 0,
                "issues_with_changelog": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Process each issue
        for issue in issues:
            issue_data = self._collect_issue_details(
                issue,
                include_comments=include_comments,
                include_changelog=include_changelog
            )
            collection_data["issues"].append(issue_data)

            if issue_data.get("comments", []):
                collection_data["summary"]["issues_with_comments"] += 1
            if issue_data.get("changelog", []):
                collection_data["summary"]["issues_with_changelog"] += 1

        # Save collected data
        output_path = f"{project_key}/issues.json"
        self.storage.save(
            collection_data,
            output_path,
            collection_type="project_issues",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(issues)} issues from {project_key}")

        return collection_data["summary"]

    def collect_issues_by_jql(
        self,
        jql: str,
        output_filename: str
    ) -> Dict[str, Any]:
        """
        Collect issues matching a JQL query.

        Args:
            jql: JQL query string
            output_filename: Filename for output

        Returns:
            Collection summary
        """
        logger.info(f"Collecting issues with JQL: {jql}")

        issues = self.api.get_issues_by_jql(jql=jql, fields="*")

        collection_data = {
            "jql": jql,
            "issues": issues,
            "summary": {
                "total_issues": len(issues)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Save collected data
        output_path = f"jql_results/{output_filename}.json"
        self.storage.save(
            collection_data,
            output_path,
            collection_type="jql_issues",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return collection_data["summary"]

    def _collect_issue_details(
        self,
        issue: Dict[str, Any],
        include_comments: bool = True,
        include_changelog: bool = True
    ) -> Dict[str, Any]:
        """
        Collect detailed information for a single issue.

        Args:
            issue: Basic issue data
            include_comments: Whether to collect comments
            include_changelog: Whether to collect change history

        Returns:
            Full issue details
        """
        issue_id = issue.get("id")
        issue_key = issue.get("key")

        issue_details = {
            "basic_info": issue,
            "full_issue": None,
            "comments": [],
            "changelog": [],
            "worklogs": [],
            "links": [],
            "attachments": []
        }

        try:
            # Get full issue data with all fields
            full_issue = self.api.get_issue_by_id(issue_id, fields="*", expand=None)
            issue_details["full_issue"] = full_issue

            # Collect comments if requested
            if include_comments and self.collectors_config.get("comments", True):
                comments = self.api.get_issue_comments(issue_id)
                issue_details["comments"] = comments

            # Collect changelog if requested
            if include_changelog and self.collectors_config.get("changelog", True):
                changelog = self.api.get_issue_changelog(issue_id)
                issue_details["changelog"] = changelog

            # Collect worklogs if requested
            if self.collectors_config.get("worklogs", True):
                worklogs = self.api.get_issue_worklogs(issue_id)
                issue_details["worklogs"] = worklogs

            # Collect issue links if requested
            if self.collectors_config.get("links", True):
                links = self.api.get_issue_links(issue_id)
                issue_details["links"] = links

            # Collect attachments if requested
            if self.collectors_config.get("attachments", True):
                attachments = self.api.get_issue_attachments(issue_id)
                issue_details["attachments"] = attachments

        except Exception as e:
            logger.error(f"Error collecting details for issue {issue_key}: {e}")
            issue_details["_error"] = str(e)

        return issue_details

    def collect_all_project_issues(
        self,
        project_keys: List[str]
    ) -> Dict[str, Any]:
        """
        Collect issues from multiple projects.

        Args:
            project_keys: List of project keys

        Returns:
            Collection summary
        """
        logger.info(f"Collecting issues from projects: {project_keys}")

        all_results = {
            "projects": {},
            "summary": {
                "total_projects": len(project_keys),
                "total_issues": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        for project_key in project_keys:
            try:
                result = self.collect_project_issues(project_key)
                all_results["projects"][project_key] = result
                all_results["summary"]["total_issues"] += result.get("total_issues", 0)
            except Exception as e:
                logger.error(f"Error collecting from {project_key}: {e}")
                all_results["projects"][project_key] = {"error": str(e)}

        return all_results["summary"]
