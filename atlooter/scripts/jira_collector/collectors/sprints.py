"""
Sprint Collector for Jira

Collects sprint and board data.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class SprintCollector:
    """Collects sprint data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        """
        Initialize sprint collector.

        Args:
            api_client: Jira API client
            storage: Data storage handler
            config: Collection configuration
        """
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_all_boards(self) -> Dict[str, Any]:
        """
        Collect all boards.

        Returns:
            Collection summary
        """
        logger.info("Collecting all boards")

        boards = self.api.get_all_boards()

        boards_data = {
            "boards": boards,
            "summary": {
                "total_boards": len(boards)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = "all_boards.json"
        self.storage.save(
            boards_data,
            output_path,
            collection_type="all_boards",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(boards)} boards")

        return boards_data["summary"]

    def collect_all_sprints(self) -> Dict[str, Any]:
        """
        Collect all sprints across all boards.

        Returns:
            Collection summary
        """
        logger.info("Collecting all sprints")

        sprints = self.api.get_all_sprints()

        sprints_data = {
            "sprints": sprints,
            "summary": {
                "total_sprints": len(sprints)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = "all_sprints.json"
        self.storage.save(
            sprints_data,
            output_path,
            collection_type="all_sprints",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(sprints)} sprints")

        return sprints_data["summary"]

    def collect_sprint_issues(
        self,
        sprint_id: int
    ) -> Dict[str, Any]:
        """
        Collect all issues in a sprint.

        Args:
            sprint_id: Sprint ID

        Returns:
            Collection summary
        """
        logger.info(f"Collecting issues for sprint {sprint_id}")

        issues = self.api.get_sprint_issues(sprint_id)

        sprints_data = {
            "sprint_id": sprint_id,
            "issues": issues,
            "summary": {
                "total_issues": len(issues)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = f"sprints/sprint_{sprint_id}_issues.json"
        self.storage.save(
            sprints_data,
            output_path,
            collection_type="sprint_issues",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(issues)} issues from sprint {sprint_id}")

        return sprints_data["summary"]

    def collect_project_epics(
        self,
        project_key: str
    ) -> Dict[str, Any]:
        """
        Collect all epics in a project.

        Args:
            project_key: Project key

        Returns:
            Collection summary
        """
        logger.info(f"Collecting epics for project: {project_key}")

        epics = self.api.get_epics(project_key)

        epics_data = {
            "project_key": project_key,
            "epics": epics,
            "summary": {
                "total_epics": len(epics)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        output_path = f"{project_key}/epics.json"
        self.storage.save(
            epics_data,
            output_path,
            collection_type="project_epics",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        logger.info(f"Collected {len(epics)} epics from {project_key}")

        return epics_data["summary"]
