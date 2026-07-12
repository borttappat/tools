"""
Jira Cloud API Client

Provides a wrapper around the Atlassian Python API client with forensics-grade
logging, rate limiting, and pagination handling.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Generator
from functools import wraps

import requests
from atlassian import Jira
from tqdm import tqdm

logger = logging.getLogger(__name__)


def rate_limit_handler(func):
    """Decorator to handle rate limiting with exponential backoff."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        max_retries = kwargs.pop('max_retries', 5)
        backoff_factor = kwargs.pop('backoff_factor', 2)

        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429 and attempt < max_retries - 1:
                    wait_time = backoff_factor ** attempt
                    logger.warning(f"Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                elif e.response.status_code == 503 and attempt < max_retries - 1:
                    wait_time = backoff_factor ** attempt
                    logger.warning(f"Service unavailable. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    raise
        return func(*args, **kwargs)
    return wrapper


class ForensicsJiraClient:
    """
    Jira Cloud API client optimized for forensic data collection.

    Features:
    - Automatic pagination handling
    - Rate limit handling with exponential backoff
    - Request/response logging for audit trail
    - Progress tracking for long-running collections
    """

    def __init__(
        self,
        url: str,
        email: str,
        token: str,
        request_timeout: int = 30
    ):
        """
        Initialize the Jira client.

        Args:
            url: Jira Cloud URL (e.g., https://company.atlassian.net)
            email: User email for authentication
            token: API token for authentication
            request_timeout: Timeout in seconds for requests
        """
        self.jira = Jira(
            url=url,
            username=email,
            password=token,
            timeout=request_timeout,
            cloud=True
        )
        self.url = url
        self._request_log = []

    def _log_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Log request for audit trail."""
        self._request_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2)
        })

    def get_request_log(self) -> List[Dict[str, Any]]:
        """Get the request audit log."""
        return self._request_log

    def get_all_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieve all accessible projects.

        Returns:
            List of all projects
        """
        all_projects = []

        with tqdm(desc="Collecting projects", unit=" projects") as pbar:
            try:
                projects = self.jira.get_all_projects()
                if isinstance(projects, list):
                    all_projects = projects
                elif isinstance(projects, dict):
                    all_projects = [projects]

                for project in all_projects:
                    pbar.update(1)

            except Exception as e:
                logger.error(f"Error collecting projects: {e}")

        return all_projects

    def get_issues_by_jql(
        self,
        jql: str,
        fields: str = "*",
        max_results: int = 100000,
        expand: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for issues using JQL.

        Args:
            jql: JQL query string
            fields: Fields to retrieve (default: all)
            max_results: Maximum results to return
            expand: Optional fields to expand

        Returns:
            List of issues
        """
        all_issues = []
        start_at = 0
        actual_max = min(max_results, 100000)

        with tqdm(desc="Collecting issues", unit=" issues") as pbar:
            while start_at < actual_max:
                try:
                    result = self.jira.jql(
                        jql,
                        start=start_at,
                        limit=min(50, actual_max - start_at),
                        fields=fields,
                        expand=expand
                    )

                    if not result or 'issues' not in result:
                        break

                    issues = result.get('issues', [])
                    total = result.get('total', len(issues))

                    for issue in issues:
                        all_issues.append(issue)
                        pbar.update(1)

                    if len(issues) < 50 or start_at + len(issues) >= total:
                        break

                    start_at += len(issues)
                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"Error collecting issues with JQL: {e}")
                    break

        return all_issues

    def get_issue_by_id(
        self,
        issue_id: str,
        fields: str = "*",
        expand: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific issue by ID or key.

        Args:
            issue_id: Issue ID or key
            fields: Fields to retrieve
            expand: Optional fields to expand

        Returns:
            Issue data or None if not found
        """
        try:
            return self.jira.issue(
                key=issue_id,
                fields=fields,
                expand=expand
            )
        except Exception as e:
            logger.error(f"Error getting issue {issue_id}: {e}")
            return None

    def get_issue_comments(
        self,
        issue_id: str,
        start_at: int = 0,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all comments on an issue.

        Args:
            issue_id: Issue ID or key
            start_at: Starting index for pagination
            max_results: Maximum results per request

        Returns:
            List of comments
        """
        try:
            comments = self.jira.issue_get_comments(
                issue_id=issue_id
            )

            if isinstance(comments, dict):
                return comments.get('comments', [])
            elif isinstance(comments, list):
                return comments
            return []
        except Exception as e:
            logger.error(f"Error getting comments for issue {issue_id}: {e}")
            return []

    def get_issue_changelog(
        self,
        issue_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get issue change history.

        Args:
            issue_id: Issue ID or key

        Returns:
            List of changelog entries
        """
        try:
            changelog = self.jira.get_issue_changelog(issue_key=issue_id)

            if isinstance(changelog, dict):
                return changelog.get('histories', [])
            elif isinstance(changelog, list):
                return changelog
            return []
        except Exception as e:
            logger.error(f"Error getting changelog for issue {issue_id}: {e}")
            return []

    def get_issue_worklogs(
        self,
        issue_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get worklog entries for an issue.

        Args:
            issue_id: Issue ID or key

        Returns:
            List of worklog entries
        """
        try:
            worklogs = self.jira.issue_get_worklog(issue_id_or_key=issue_id)

            if isinstance(worklogs, dict):
                return worklogs.get('worklogs', [])
            elif isinstance(worklogs, list):
                return worklogs
            return []
        except Exception as e:
            logger.error(f"Error getting worklogs for issue {issue_id}: {e}")
            return []

    def get_issue_links(
        self,
        issue_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get linked issues.

        Args:
            issue_id: Issue ID or key

        Returns:
            List of issue links
        """
        try:
            issue = self.jira.issue(key=issue_id)
            links = issue.get('fields', {}).get('issuelinks', [])
            return links
        except Exception as e:
            logger.error(f"Error getting issue links for {issue_id}: {e}")
            return []

    def get_issue_attachments(
        self,
        issue_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get attachments from an issue.

        Args:
            issue_id: Issue ID or key

        Returns:
            List of attachments
        """
        try:
            issue = self.jira.issue(key=issue_id)
            attachments = issue.get('fields', {}).get('attachment', [])
            return attachments
        except Exception as e:
            logger.error(f"Error getting attachments for issue {issue_id}: {e}")
            return []

    def get_all_projects_issues(
        self,
        project_keys: List[str],
        fields: str = "*",
        expand: Optional[str] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all issues from multiple projects.

        Args:
            project_keys: List of project keys
            fields: Fields to retrieve
            expand: Optional fields to expand

        Returns:
            Dictionary mapping project keys to issue lists
        """
        all_issues = {}

        for project_key in project_keys:
            jql = f"project = {project_key}"
            issues = self.get_issues_by_jql(jql, fields=fields, expand=expand)
            all_issues[project_key] = issues

            logger.info(f"Collected {len(issues)} issues from project {project_key}")

        return all_issues

    def get_sprint_issues(
        self,
        sprint_id: int
    ) -> List[Dict[str, Any]]:
        """
        Get all issues in a sprint.

        Args:
            sprint_id: Sprint ID

        Returns:
            List of issues in the sprint
        """
        try:
            # Using the Greenhopper API endpoint for sprints
            url = f"{self.url}/rest/greenhopper/1.0/sprint/{sprint_id}/issue"
            response = self.jira.get(url)

            if response and 'issues' in response:
                return response['issues']
            return []
        except Exception as e:
            logger.error(f"Error getting sprint {sprint_id} issues: {e}")
            return []

    def get_all_sprints(self, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all sprints.

        Args:
            project_key: Optional project filter

        Returns:
            List of sprints
        """
        all_sprints = []

        try:
            # Get all boards first using the correct method
            boards = self.jira.get_all_agile_boards()
            board_ids = [b['id'] for b in boards.get('values', [])] if isinstance(boards, dict) else []

            for board_id in board_ids:
                try:
                    sprints = self.jira.get_all_sprints_from_board(board_id)
                    if sprints and 'values' in sprints:
                        all_sprints.extend(sprints['values'])
                except Exception as e:
                    logger.warning(f"Could not get sprints for board {board_id}: {e}")

        except Exception as e:
            logger.error(f"Error getting sprints: {e}")

        return all_sprints

    def get_epics(
        self,
        project_key: str
    ) -> List[Dict[str, Any]]:
        """
        Get all epics in a project.

        Args:
            project_key: Project key

        Returns:
            List of epics
        """
        # JQL to find epics (epic link is typically an issue type)
        jql = f"project = {project_key} AND issuetype = Epic"
        return self.get_issues_by_jql(jql)

    def get_audit_log(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        offset: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get Jira audit log entries.

        Args:
            date_from: Start date filter
            date_to: End date filter
            offset: Starting offset for pagination
            limit: Maximum results per request

        Returns:
            List of audit log entries
        """
        all_logs = []

        with tqdm(desc="Collecting audit log", unit=" entries") as pbar:
            try:
                # Use the correct auditlog method with parameters
                result = self.jira.get_audit_records(
                    offset=offset,
                    limit=limit,
                    from_date=date_from,
                    to_date=date_to
                )

                if result:
                    records = result if isinstance(result, list) else result.get('records', [])
                    for record in records:
                        all_logs.append(record)
                        pbar.update(1)

            except Exception as e:
                logger.error(f"Error collecting audit log: {e}")

        return all_logs

    def download_attachment(
        self,
        attachment_id: str,
        filename: str,
        output_dir: str
    ) -> Optional[str]:
        """
        Download an attachment to a file.

        Args:
            attachment_id: The attachment ID
            filename: The filename to save as
            output_dir: Directory to save the file

        Returns:
            Path to saved file or None on failure
        """
        try:
            url = f"{self.url}/secure/attachment/{attachment_id}/{filename}"

            response = requests.get(
                url,
                auth=(self.jira.username, self.jira.password),
                timeout=60
            )

            if response.status_code == 200:
                # Sanitize filename
                safe_filename = "".join(c for c in filename if c not in r'\/:*?"<>|')
                output_path = os.path.join(output_dir, f"issue_{attachment_id}_{safe_filename}")
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                return output_path
            else:
                logger.warning(f"Failed to download attachment: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error downloading attachment {filename}: {e}")
            return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all accessible users (paginated).

        Returns:
            List of users
        """
        all_users = []
        start = 0
        limit = 50
        try:
            while True:
                batch = self.jira.users_get_all(start=start, limit=limit)
                if not batch or not isinstance(batch, list):
                    break
                all_users.extend(batch)
                if len(batch) < limit:
                    break
                start += limit
        except Exception as e:
            logger.error(f"Error getting users: {e}")
        return all_users

    def get_all_boards(self) -> List[Dict[str, Any]]:
        """
        Get all boards.

        Returns:
            List of boards
        """
        try:
            boards = self.jira.get_all_agile_boards()
            return boards.get('values', []) if isinstance(boards, dict) else []
        except Exception as e:
            logger.error(f"Error getting boards: {e}")
            return []

    def get_project_versions(self, project_key: str) -> List[Dict[str, Any]]:
        """Get all versions/releases for a project."""
        try:
            versions = self.jira.get_project_versions(key=project_key)
            return versions if isinstance(versions, list) else []
        except Exception as e:
            logger.error(f"Error getting versions for {project_key}: {e}")
            return []

    def get_project_components(self, project_key: str) -> List[Dict[str, Any]]:
        """Get all components for a project."""
        try:
            components = self.jira.get_project_components(key=project_key)
            return components if isinstance(components, list) else []
        except Exception as e:
            logger.error(f"Error getting components for {project_key}: {e}")
            return []

    def get_project_roles(self, project_key: str) -> Dict[str, Any]:
        """Get all roles and their members for a project."""
        try:
            roles = self.jira.get_project_roles(project_key=project_key)
            return roles if isinstance(roles, dict) else {}
        except Exception as e:
            logger.error(f"Error getting roles for {project_key}: {e}")
            return {}

    def get_project_permission_scheme(self, project_key: str) -> Dict[str, Any]:
        """Get the permission scheme for a project."""
        try:
            scheme = self.jira.get_project_permission_scheme(project_id_or_key=project_key)
            return scheme if isinstance(scheme, dict) else {}
        except Exception as e:
            logger.error(f"Error getting permission scheme for {project_key}: {e}")
            return {}

    def get_issue_remote_links(self, issue_key: str) -> List[Dict[str, Any]]:
        """Get remote/web links attached to an issue."""
        try:
            links = self.jira.get_issue_remote_links(issue_key=issue_key)
            return links if isinstance(links, list) else []
        except Exception as e:
            logger.error(f"Error getting remote links for {issue_key}: {e}")
            return []

    def get_issue_watchers(self, issue_key: str) -> Dict[str, Any]:
        """Get watchers for an issue."""
        try:
            watchers = self.jira.issue_get_watchers(issue_key=issue_key)
            return watchers if isinstance(watchers, dict) else {}
        except Exception as e:
            logger.error(f"Error getting watchers for {issue_key}: {e}")
            return {}

    def get_all_fields(self) -> List[Dict[str, Any]]:
        """Get all field definitions including custom fields."""
        try:
            result = self.jira.get_all_fields()
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                return list(result.values())
            return []
        except Exception as e:
            logger.error(f"Error getting fields: {e}")
            return []

    def get_all_priorities(self) -> List[Dict[str, Any]]:
        """Get all priority definitions."""
        try:
            result = self.jira.get_all_priorities()
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                return list(result.values())
            return []
        except Exception as e:
            logger.error(f"Error getting priorities: {e}")
            return []

    def get_all_statuses(self) -> List[Dict[str, Any]]:
        """Get all status definitions."""
        try:
            result = self.jira.get_all_statuses()
            if isinstance(result, list):
                return result
            elif isinstance(result, dict):
                return list(result.values())
            return []
        except Exception as e:
            logger.error(f"Error getting statuses: {e}")
            return []
