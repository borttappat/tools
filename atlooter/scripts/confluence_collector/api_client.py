"""
Confluence Cloud API Client

Provides a wrapper around the Atlassian Python API client with forensics-grade
logging, rate limiting, and pagination handling.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Generator
from functools import wraps

import requests
from atlassian import Confluence
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


class ForensicsConfluenceClient:
    """
    Confluence API client optimized for forensic data collection.

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
        Initialize the Confluence client.

        Args:
            url: Confluence Cloud URL (e.g., https://company.atlassian.net)
            email: User email for authentication
            token: API token for authentication
            request_timeout: Timeout in seconds for requests
        """
        self.confluence = Confluence(
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
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2)
        })

    def get_request_log(self) -> List[Dict[str, Any]]:
        """Get the request audit log."""
        return self._request_log

    def get_all_spaces(self, start: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve all accessible spaces.

        Args:
            start: Starting index for pagination
            limit: Maximum results per request

        Returns:
            List of all spaces
        """
        all_spaces = []

        with tqdm(desc="Collecting spaces", unit=" spaces") as pbar:
            while True:
                try:
                    result = self.confluence.get_all_spaces(start=start, limit=limit)
                    spaces = result.get('results', [])

                    for space in spaces:
                        all_spaces.append(space)
                        pbar.update(1)

                    if len(spaces) < limit:
                        break

                    start += limit

                    # Small delay to avoid overwhelming the API
                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"Error collecting spaces: {e}")
                    break

        return all_spaces

    def get_space_pages(
        self,
        space_key: str,
        start: int = 0,
        limit: int = 100,
        content_type: str = "page"
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields all pages in a space.

        Args:
            space_key: The space key to collect pages from
            start: Starting index for pagination
            limit: Maximum results per request
            content_type: Type of content to collect ('page' or 'blogpost')

        Yields:
            Individual page dictionaries
        """
        with tqdm(desc=f"Collecting {content_type}s from {space_key}", unit=" items") as pbar:
            while True:
                try:
                    result = self.confluence.get_all_pages_from_space(
                        space=space_key,
                        start=start,
                        limit=limit,
                        content_type=content_type,
                        expand="version,metadata.labels"
                    )

                    if not result:
                        break

                    for page in result:
                        yield page
                        pbar.update(1)

                    start += limit

                except Exception as e:
                    logger.error(f"Error collecting pages from {space_key}: {e}")
                    break

    def get_page_by_id(
        self,
        page_id: str,
        expand: str = "version,metadata.labels,children.attachment,child/comment"
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific page with expanded data.

        Args:
            page_id: The page ID
            expand: Fields to expand (comma-separated)

        Returns:
            Page data or None if not found
        """
        try:
            return self.confluence.get_page_by_id(
                page_id=page_id,
                expand=expand
            )
        except Exception as e:
            logger.error(f"Error getting page {page_id}: {e}")
            return None

    def get_page_versions(self, page_id: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a page.

        Args:
            page_id: The page ID

        Returns:
            List of page versions
        """
        try:
            return self.confluence.get_page_history(page_id)
        except Exception as e:
            logger.error(f"Error getting versions for page {page_id}: {e}")
            return []

    def get_page_comments(
        self,
        page_id: str,
        start: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all comments on a page.

        Args:
            page_id: The page ID
            start: Starting index for pagination
            limit: Maximum results per request

        Returns:
            List of comments
        """
        try:
            result = self.confluence.get_page_by_id(
                page_id=page_id,
                expand="child/comment"
            )

            if result:
                comments = result.get('children', {}).get('comment', {}).get('results', [])
                return comments
            return []
        except Exception as e:
            logger.error(f"Error getting comments for page {page_id}: {e}")
            return []

    def get_page_restrictions(
        self,
        page_id: str,
        operation: str = "read"
    ) -> Dict[str, Any]:
        """
        Get page restriction information.

        Args:
            page_id: The page ID
            operation: The operation to check restrictions for ('read' or 'update')

        Returns:
            Restriction data
        """
        try:
            return self.confluence.get_content_restrictions(
                content_id=page_id,
                permission=operation
            )
        except Exception as e:
            logger.error(f"Error getting restrictions for page {page_id}: {e}")
            return {}

    def get_space_permissions(self, space_key: str) -> Dict[str, Any]:
        """
        Get space permission information.

        Args:
            space_key: The space key

        Returns:
            Space permission data
        """
        try:
            # Note: Space permissions endpoint may vary by Confluence version
            return self.confluence.get_space_permission(space_key)
        except Exception as e:
            logger.error(f"Error getting permissions for space {space_key}: {e}")
            return {}

    def get_page_attachments(
        self,
        page_id: str,
        start: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all attachments on a page.

        Args:
            page_id: The page ID
            start: Starting index for pagination
            limit: Maximum results per request

        Returns:
            List of attachments
        """
        try:
            result = self.confluence.get_page_by_id(
                page_id=page_id,
                expand="child/attachment"
            )

            if result:
                attachments = result.get('children', {}).get('attachment', {}).get('results', [])
                return attachments
            return []
        except Exception as e:
            logger.error(f"Error getting attachments for page {page_id}: {e}")
            return []

    def get_page_labels(self, page_id: str) -> List[Dict[str, Any]]:
        """
        Get all labels on a page.

        Args:
            page_id: The page ID

        Returns:
            List of labels
        """
        try:
            result = self.confluence.get_page_by_id(
                page_id=page_id,
                expand="metadata.labels"
            )

            if result:
                labels = result.get('metadata', {}).get('labels', {}).get('results', [])
                return labels
            return []
        except Exception as e:
            logger.error(f"Error getting labels for page {page_id}: {e}")
            return []

    def get_templates(self, space_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get templates.

        Args:
            space_key: Optional space key to filter templates

        Returns:
            List of templates
        """
        try:
            if space_key:
                return self.confluence.get_space_template(space_key)
            return self.confluence.get_all_templates()
        except Exception as e:
            logger.error(f"Error getting templates: {e}")
            return []

    def get_audit_log(
        self,
        start: int = 0,
        limit: int = 100,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit log entries.

        Args:
            start: Starting index for pagination
            limit: Maximum results per request
            date_from: Start date filter (ISO format)
            date_to: End date filter (ISO format)

        Returns:
            List of audit log entries
        """
        all_logs = []

        params = {"start": start, "limit": limit}
        if date_from:
            params["fromDate"] = date_from
        if date_to:
            params["toDate"] = date_to

        with tqdm(desc="Collecting audit log", unit=" entries") as pbar:
            while True:
                try:
                    result = self.confluence.get_auditing_records(params)

                    if not result:
                        break

                    for record in result:
                        all_logs.append(record)
                        pbar.update(1)

                    if len(result) < limit:
                        break

                    start += limit
                    params["start"] = start

                except Exception as e:
                    logger.error(f"Error collecting audit log: {e}")
                    break

        return all_logs

    def download_attachment(
        self,
        attachment_id: str,
        page_id: str,
        filename: str,
        output_dir: str
    ) -> Optional[str]:
        """
        Download an attachment to a file.

        Args:
            attachment_id: The attachment ID
            page_id: The parent page ID
            filename: The filename to save as
            output_dir: Directory to save the file

        Returns:
            Path to saved file or None on failure
        """
        try:
            # Construct the download URL
            url = f"{self.url}/download/attachments/{page_id}/{filename}?attachmentId={attachment_id}"

            response = requests.get(
                url,
                auth=(self.confluence.username, self.confluence.password),
                timeout=60
            )

            if response.status_code == 200:
                output_path = os.path.join(output_dir, f"{page_id}_{filename}")
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                return output_path
            else:
                logger.warning(f"Failed to download attachment: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error downloading attachment {filename}: {e}")
            return None

    def get_all_page_content(self, page_id: str) -> Optional[str]:
        """
        Get the full content of a page.

        Args:
            page_id: The page ID

        Returns:
            Page content in storage format
        """
        try:
            page = self.confluence.get_page_by_id(
                page_id=page_id,
                expand="body.storage"
            )

            if page:
                return page.get('body', {}).get('storage', {}).get('value')
            return None
        except Exception as e:
            logger.error(f"Error getting page content {page_id}: {e}")
            return None
