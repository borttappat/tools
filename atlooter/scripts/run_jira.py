#!/usr/bin/env python3
"""
Jira Cloud Forensics Collector

Main execution script for collecting Jira data for forensic analysis.

Usage:
    python run_jira.py --config config/jira_config.yaml

Example:
    # Collect all data from all projects
    python run_jira.py

    # Collect from specific projects only
    python run_jira.py --projects PROJ1 PROJ2
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml
from tqdm.contrib.logging import logging_redirect_tqdm

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from jira_collector.api_client import ForensicsJiraClient
from jira_collector.utils.storage import DataStorage
from jira_collector.utils.auth import load_config, get_credentials_from_env, validate_credentials
from jira_collector.collectors import (
    IssueCollector, CommentCollector, WorklogCollector,
    LinkCollector, SprintCollector, AttachmentCollector, AuditCollector,
    ProjectMetaCollector, RemoteLinkCollector, WatcherCollector
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Jira Cloud Forensics Collector"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/jira_config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--projects",
        type=str,
        nargs="+",
        help="Specific project keys to collect (default: all projects)"
    )
    parser.add_argument(
        "--jql",
        type=str,
        help="JQL query to filter issues"
    )
    parser.add_argument(
        "--download-files",
        action="store_true",
        default=True,
        help="Download attachment files"
    )
    parser.add_argument(
        "--no-download-files",
        action="store_true",
        help="Skip downloading attachment files"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)

    try:
        config = load_config(str(config_path))
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)

    # Get credentials
    creds = get_credentials_from_env("jira")

    # Validate credentials
    if not validate_credentials(creds):
        logger.error("Missing required credentials. Set JIRA_URL, JIRA_EMAIL, JIRA_TOKEN")
        sys.exit(1)

    # Initialize API client
    logger.info("Connecting to Jira...")
    api_client = ForensicsJiraClient(
        url=creds["url"],
        email=creds["email"],
        token=creds["token"]
    )

    # Initialize storage
    output_dir = config.get("jira", {}).get("output", {}).get("directory", "output/jira")
    storage = DataStorage(
        base_dir=output_dir,
        format="json",
        include_metadata=True
    )

    # Initialize collectors
    collection_config = config.get("jira", {}).get("collection", {})
    collectors_config = collection_config.get("collectors", {})

    issue_collector = IssueCollector(api_client, storage, config)
    comment_collector = CommentCollector(api_client, storage, config)
    worklog_collector = WorklogCollector(api_client, storage, config)
    link_collector = LinkCollector(api_client, storage, config)
    sprint_collector = SprintCollector(api_client, storage, config)
    attachment_collector = AttachmentCollector(api_client, storage, config)
    audit_collector = AuditCollector(api_client, storage, config)
    project_meta_collector = ProjectMetaCollector(api_client, storage, config)
    remote_link_collector = RemoteLinkCollector(api_client, storage, config)
    watcher_collector = WatcherCollector(api_client, storage, config)

    # Determine which projects to collect
    if args.projects:
        project_keys = args.projects
        logger.info(f"Collecting from specified projects: {project_keys}")
    elif args.jql:
        project_keys = []
        logger.info(f"Collecting based on JQL query: {args.jql}")
    else:
        logger.info("Collecting from all accessible projects...")
        all_projects = api_client.get_all_projects()
        project_keys = [p.get("key") for p in all_projects]
        logger.info(f"Found {len(project_keys)} accessible projects")

    # Collection summary
    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "projects_processed": [],
        "collectors_run": []
    }

    # Determine which collectors to run
    collectors_to_run = []
    for name in [
        "issues", "comments", "worklogs", "links", "attachments",
        "sprints", "epics", "audit_log", "users", "boards",
        "project_meta", "remote_links", "watchers",
        "fields", "priorities", "statuses"
    ]:
        if collectors_config.get(name, True):
            collectors_to_run.append(name)

    logger.info(f"Active collectors: {', '.join(collectors_to_run)}")

    with logging_redirect_tqdm():

        # ── Global / instance-wide data ──────────────────────────────────────

        print()
        logger.info("Collecting instance-wide data...")

        if "boards" in collectors_to_run:
            try:
                sprint_collector.collect_all_boards()
                summary["collectors_run"].append("boards")
            except Exception as e:
                logger.error(f"Boards collection failed: {e}")

        if "sprints" in collectors_to_run:
            try:
                sprint_collector.collect_all_sprints()
                summary["collectors_run"].append("sprints")
            except Exception as e:
                logger.error(f"Sprints collection failed: {e}")

        if "fields" in collectors_to_run:
            try:
                fields = api_client.get_all_fields()
                storage.save(
                    {"fields": fields, "total": len(fields)},
                    "global/fields.json",
                    collection_type="instance_fields"
                )
                logger.info(f"Collected {len(fields)} field definitions")
                summary["collectors_run"].append("fields")
            except Exception as e:
                logger.error(f"Fields collection failed: {e}")

        if "priorities" in collectors_to_run:
            try:
                priorities = api_client.get_all_priorities()
                storage.save(
                    {"priorities": priorities, "total": len(priorities)},
                    "global/priorities.json",
                    collection_type="instance_priorities"
                )
                logger.info(f"Collected {len(priorities)} priorities")
                summary["collectors_run"].append("priorities")
            except Exception as e:
                logger.error(f"Priorities collection failed: {e}")

        if "statuses" in collectors_to_run:
            try:
                statuses = api_client.get_all_statuses()
                storage.save(
                    {"statuses": statuses, "total": len(statuses)},
                    "global/statuses.json",
                    collection_type="instance_statuses"
                )
                logger.info(f"Collected {len(statuses)} statuses")
                summary["collectors_run"].append("statuses")
            except Exception as e:
                logger.error(f"Statuses collection failed: {e}")

        if "users" in collectors_to_run:
            try:
                users = api_client.get_all_users()
                storage.save(
                    {"users": users, "total": len(users)},
                    "global/users.json",
                    collection_type="instance_users"
                )
                logger.info(f"Collected {len(users)} users")
                summary["collectors_run"].append("users")
            except Exception as e:
                logger.error(f"Users collection failed: {e}")

        # ── Per-project data ──────────────────────────────────────────────────

        for project_key in project_keys:
            print()
            logger.info(f"Processing project: {project_key}")

            project_result = {
                "project_key": project_key,
                "collectors": {}
            }

            if "project_meta" in collectors_to_run:
                try:
                    result = project_meta_collector.collect_project_meta(project_key)
                    project_result["collectors"]["project_meta"] = result
                except Exception as e:
                    logger.error(f"Project metadata collection failed: {e}")
                    project_result["collectors"]["project_meta"] = f"error: {e}"

            if "issues" in collectors_to_run:
                try:
                    result = issue_collector.collect_project_issues(
                        project_key,
                        include_comments=True,
                        include_changelog=True
                    )
                    project_result["collectors"]["issues"] = result
                except Exception as e:
                    logger.error(f"Issues collection failed: {e}")
                    project_result["collectors"]["issues"] = f"error: {e}"

            if "comments" in collectors_to_run:
                try:
                    result = comment_collector.collect_project_comments(project_key)
                    project_result["collectors"]["comments"] = result
                except Exception as e:
                    logger.error(f"Comments collection failed: {e}")
                    project_result["collectors"]["comments"] = f"error: {e}"

            if "worklogs" in collectors_to_run:
                try:
                    result = worklog_collector.collect_project_worklogs(project_key)
                    project_result["collectors"]["worklogs"] = result
                except Exception as e:
                    logger.error(f"Worklogs collection failed: {e}")
                    project_result["collectors"]["worklogs"] = f"error: {e}"

            if "links" in collectors_to_run:
                try:
                    result = link_collector.collect_project_links(project_key)
                    project_result["collectors"]["links"] = result
                except Exception as e:
                    logger.error(f"Links collection failed: {e}")
                    project_result["collectors"]["links"] = f"error: {e}"

            if "remote_links" in collectors_to_run:
                try:
                    result = remote_link_collector.collect_project_remote_links(project_key)
                    project_result["collectors"]["remote_links"] = result
                except Exception as e:
                    logger.error(f"Remote links collection failed: {e}")
                    project_result["collectors"]["remote_links"] = f"error: {e}"

            if "attachments" in collectors_to_run:
                try:
                    result = attachment_collector.collect_project_attachments(project_key)
                    project_result["collectors"]["attachments"] = result
                except Exception as e:
                    logger.error(f"Attachments collection failed: {e}")
                    project_result["collectors"]["attachments"] = f"error: {e}"

            if "watchers" in collectors_to_run:
                try:
                    result = watcher_collector.collect_project_watchers(project_key)
                    project_result["collectors"]["watchers"] = result
                except Exception as e:
                    logger.error(f"Watchers collection failed: {e}")
                    project_result["collectors"]["watchers"] = f"error: {e}"

            if "epics" in collectors_to_run:
                try:
                    result = sprint_collector.collect_project_epics(project_key)
                    project_result["collectors"]["epics"] = result
                except Exception as e:
                    logger.error(f"Epics collection failed: {e}")
                    project_result["collectors"]["epics"] = f"error: {e}"

            summary["projects_processed"].append(project_result)

        # ── Final global collectors ───────────────────────────────────────────

        if "audit_log" in collectors_to_run:
            print()
            logger.info("Collecting audit log...")
            try:
                audit_collector.collect_audit_log()
                summary["collectors_run"].append("audit_log")
            except Exception as e:
                logger.error(f"Audit log collection failed: {e}")

    # Save final summary
    summary["completed_at"] = datetime.now(timezone.utc).isoformat()
    summary["total_projects"] = len(project_keys)

    summary_path = storage.save(
        summary,
        "collection_summary.json",
        collection_type="collection_summary"
    )

    print()
    logger.info("Collection complete!")
    logger.info(f"Summary saved to: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
