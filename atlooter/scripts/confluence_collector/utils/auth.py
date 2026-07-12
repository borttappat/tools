"""
Authentication Utilities for Confluence Collector

Handles configuration loading and credential management.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file with environment variable expansion.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary
    """
    # Load environment variables from .env file if it exists
    load_dotenv()

    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # Recursively expand environment variables
    return _expand_env_vars(config)


def _expand_env_vars(obj: Any) -> Any:
    """Recursively expand environment variables in config."""
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        # Handle ${VAR_NAME} pattern
        if obj.startswith('${') and obj.endswith('}'):
            var_name = obj[2:-1]
            return os.getenv(var_name, obj)
        # Handle $VAR_NAME pattern (for values without surrounding text)
        elif obj.startswith('$'):
            var_name = obj[1:]
            return os.getenv(var_name, obj)
        return obj
    else:
        return obj


def get_credentials_from_env(
    service: str
) -> Dict[str, Optional[str]]:
    """
    Get credentials from environment variables.

    Args:
        service: Service name ('confluence' or 'jira')

    Returns:
        Dictionary with url, email, token
    """
    prefix = service.upper()

    return {
        "url": os.getenv(f"{prefix}_URL"),
        "email": os.getenv(f"{prefix}_EMAIL"),
        "token": os.getenv(f"{prefix}_TOKEN")
    }


def validate_credentials(creds: Dict[str, Optional[str]]) -> bool:
    """
    Validate that all required credentials are present.

    Args:
        creds: Credentials dictionary

    Returns:
        True if valid, False otherwise
    """
    required = ["url", "email", "token"]
    for field in required:
        if not creds.get(field):
            return False
    return True
