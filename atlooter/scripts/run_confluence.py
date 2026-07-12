#!/usr/bin/env python3
"""
Confluence Cloud Forensics Collector

Main execution script for collecting Confluence data for forensic analysis.

Usage:
    python run_confluence.py --config config/confluence_config.yaml

Example:
    # Collect all data from all spaces
    python run_confluence.py

    # Collect from specific spaces only
    python run_confluence.py --spaces DEMO DOC
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path

import yaml
from tqdm import tqdm

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from confluence_collector.api_client import ForensicsConfluenceClient
from confluence_collector.utils.storage import DataStorage
from confluence_collector.utils.auth import load_config, get_credentials_from_env, validate_credentials
from confluence_collector.collectors import (
    PageCollector, CommentCollector, RestrictionCollector,
    AttachmentCollector, SpaceCollector, TemplateCollector, AuditCollector
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
        description="Confluence Cloud Forensics Collector"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/confluence_config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--spaces",
        type=str,
        nargs="+",
        help="Specific space keys to collect (default: all spaces)"
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
    creds = get_credentials_from_env("confluence")

    # Validate credentials
    if not validate_credentials(creds):
        logger.error("Missing required credentials. Set CONFLUENCE_URL, CONFLUENCE_EMAIL, CONFLUENCE_TOKEN")
        sys.exit(1)

    # Initialize API client
    logger.info("Connecting to Confluence...")
    api_client = ForensicsConfluenceClient(
        url=creds["url"],
        email=creds["email"],
        token=creds["token"]
    )

    # Initialize storage
    output_dir = config.get("confluence", {}).get("output", {}).get("directory", "output/confluence")
    storage = DataStorage(
        base_dir=output_dir,
        format="json",
        include_metadata=True
    )

    # Initialize collectors
    collection_config = config.get("confluence", {}).get("collection", {})
    collectors_config = collection_config.get("collectors", {})

    page_collector = PageCollector(api_client, storage, config)
    comment_collector = CommentCollector(api_client, storage, config)
    restriction_collector = RestrictionCollector(api_client, storage, config)
    attachment_collector = AttachmentCollector(api_client, storage, config)
    space_collector = SpaceCollector(api_client, storage, config)
    template_collector = TemplateCollector(api_client, storage, config)
    audit_collector = AuditCollector(api_client, storage, config)

    # Determine which spaces to collect
    if args.spaces:
        space_keys = args.spaces
        logger.info(f"Collecting from specified spaces: {space_keys}")
    else:
        # Get all spaces
        logger.info("Collecting from all accessible spaces...")
        all_spaces = space_collector.collect_all_spaces()
        space_keys = [s["key"] for s in all_spaces.get("spaces", [])]
        logger.info(f"Found {len(space_keys)} accessible spaces")

    # Collection summary
    summary = {
        "started_at": datetime.utcnow().isoformat(),
        "spaces_processed": [],
        "collectors_run": []
    }

    # Process each space
    collectors_to_run = []
    if collectors_config.get("spaces", True):
        collectors_to_run.append("spaces")
    if collectors_config.get("pages", True):
        collectors_to_run.append("pages")
    if collectors_config.get("comments", True):
        collectors_to_run.append("comments")
    if collectors_config.get("restrictions", True):
        collectors_to_run.append("restrictions")
    if collectors_config.get("attachments", True):
        collectors_to_run.append("attachments")
    if collectors_config.get("templates", True):
        collectors_to_run.append("templates")
    if collectors_config.get("audit_log", True):
        collectors_to_run.append("audit_log")

    logger.info(f"Active collectors: {', '.join(collectors_to_run)}")

    for space_key in space_keys:
        logger.info(f"\nProcessing space: {space_key}")
        space_result = {
            "space_key": space_key,
            "collectors": {}
        }

        # Run enabled collectors
        if "spaces" in collectors_to_run:
            try:
                restriction_collector.collect_space_permissions(space_key)
                space_result["collectors"]["permissions"] = "complete"
            except Exception as e:
                logger.error(f"Permissions collection failed: {e}")
                space_result["collectors"]["permissions"] = f"error: {e}"

        if "pages" in collectors_to_run:
            try:
                result = page_collector.collect_space_pages(space_key)
                space_result["collectors"]["pages"] = result
            except Exception as e:
                logger.error(f"Pages collection failed: {e}")
                space_result["collectors"]["pages"] = f"error: {e}"

        if "restrictions" in collectors_to_run:
            try:
                result = restriction_collector.collect_all_space_restrictions(space_key)
                space_result["collectors"]["restrictions"] = result
            except Exception as e:
                logger.error(f"Restrictions collection failed: {e}")
                space_result["collectors"]["restrictions"] = f"error: {e}"

        if "attachments" in collectors_to_run:
            try:
                result = attachment_collector.collect_space_attachments(space_key)
                space_result["collectors"]["attachments"] = result
            except Exception as e:
                logger.error(f"Attachments collection failed: {e}")
                space_result["collectors"]["attachments"] = f"error: {e}"

        summary["spaces_processed"].append(space_result)

    # Collect global data
    logger.info("\nCollecting global data...")

    if "templates" in collectors_to_run:
        try:
            template_collector.collect_all_templates()
            summary["collectors_run"].append("templates")
        except Exception as e:
            logger.error(f"Templates collection failed: {e}")

    if "audit_log" in collectors_to_run:
        try:
            audit_collector.collect_audit_log()
            summary["collectors_run"].append("audit_log")
        except Exception as e:
            logger.error(f"Audit log collection failed: {e}")

    # Save final summary
    summary["completed_at"] = datetime.utcnow().isoformat()
    summary["total_spaces"] = len(space_keys)

    summary_path = storage.save(
        summary,
        "collection_summary.json",
        collection_type="collection_summary"
    )

    logger.info(f"\nCollection complete!")
    logger.info(f"Summary saved to: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
