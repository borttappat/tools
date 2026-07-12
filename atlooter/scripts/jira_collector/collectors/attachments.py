"""
Attachment Collector for Jira

Collects issue attachments and their metadata.
Only processes issues that actually have attachments.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from ..api_client import ForensicsJiraClient
from ..utils.storage import DataStorage

logger = logging.getLogger(__name__)


class AttachmentCollector:
    """Collects attachment data from Jira."""

    def __init__(
        self,
        api_client: ForensicsJiraClient,
        storage: DataStorage,
        config: Dict[str, Any]
    ):
        self.api = api_client
        self.storage = storage
        self.config = config.get("collection", {})
        self.download_attachments = config.get("download_files", True)

    def collect_project_attachments(
        self,
        project_key: str
    ) -> Dict[str, Any]:
        """
        Collect all attachments from issues in a project.
        Fetches attachment metadata inline with the issue list to avoid
        extra API calls. Only processes and logs issues with attachments.

        Args:
            project_key: Project key to collect from

        Returns:
            Collection summary
        """
        logger.info(f"Collecting attachments from project: {project_key}")

        # Fetch issues with attachment field included - no extra API calls needed
        jql = f"project = {project_key}"
        issues = self.api.get_issues_by_jql(jql=jql, fields="key,attachment")

        all_attachments = {
            "project_key": project_key,
            "issues": {},
            "summary": {
                "issues_with_attachments": 0,
                "total_attachments": 0,
                "downloaded_count": 0,
                "failed_count": 0
            },
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }

        for issue in issues:
            issue_key = issue.get("key")
            attachments = issue.get("fields", {}).get("attachment", [])

            if not attachments:
                continue

            logger.info(f"  {issue_key}: {len(attachments)} attachment(s)")

            downloaded = []
            failed = []

            if self.download_attachments:
                output_dir = self.storage.ensure_directory(
                    "attachments", f"issue_{issue_key}"
                )
                for attachment in attachments:
                    attachment_id = attachment.get("id")
                    filename = attachment.get("filename")
                    if attachment_id and filename:
                        result = self.api.download_attachment(
                            attachment_id=attachment_id,
                            filename=filename,
                            output_dir=str(output_dir)
                        )
                        if result:
                            downloaded.append({
                                "filename": filename,
                                "saved_as": result,
                                "attachment_id": attachment_id
                            })
                        else:
                            failed.append({
                                "filename": filename,
                                "attachment_id": attachment_id,
                                "error": "Download failed"
                            })

            all_attachments["issues"][issue_key] = {
                "attachments": attachments,
                "count": len(attachments),
                "downloaded_files": downloaded,
                "failed_downloads": failed
            }
            all_attachments["summary"]["issues_with_attachments"] += 1
            all_attachments["summary"]["total_attachments"] += len(attachments)
            all_attachments["summary"]["downloaded_count"] += len(downloaded)
            all_attachments["summary"]["failed_count"] += len(failed)

        logger.info(
            f"  {all_attachments['summary']['issues_with_attachments']} issues with attachments, "
            f"{all_attachments['summary']['total_attachments']} total"
        )

        output_path = f"{project_key}/attachments/all_attachments_summary.json"
        self.storage.save(
            all_attachments,
            output_path,
            collection_type="project_attachments_summary",
            include_request_log=True,
            request_log=self.api.get_request_log()
        )

        return all_attachments["summary"]
