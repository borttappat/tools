"""
Project Metadata Collector for Jira

Collects project-level metadata: versions/releases, components,
roles, and permission schemes.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class ProjectMetaCollector:
    """Collects project metadata from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})

    def collect_project_meta(self, project_key: str) -> Dict[str, Any]:
        """
        Collect versions, components, roles, and permission scheme for a project.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting project metadata for: {project_key}")

        versions = self.api.get_project_versions(project_key)
        components = self.api.get_project_components(project_key)
        roles = self.api.get_project_roles(project_key)
        permission_scheme = self.api.get_project_permission_scheme(project_key)

        meta = {
            "project_key": project_key,
            "versions": versions,
            "components": components,
            "roles": roles,
            "permission_scheme": permission_scheme,
            "summary": {
                "total_versions": len(versions),
                "total_components": len(components),
                "total_roles": len(roles)
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        logger.info(
            f"  {len(versions)} version(s), {len(components)} component(s), "
            f"{len(roles)} role(s)"
        )

        output_path = f"{project_key}/project_meta.json"
        self.storage.save(
            meta,
            output_path,
            collection_type="project_meta",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return meta["summary"]
