"""
Tango Text Extractor
Unified text extraction using Apache Tika for rich document formats,
with fallback to direct reading for plain text files.
"""

# File extensions that benefit from Tika extraction
TIKA_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'odt', 'ods', 'odp', 'rtf', 'eml', 'msg', 'pages',
    'numbers', 'key'
}

try:
    from tika import parser as tika_parser
    # Suppress Tika's own logging noise
    import logging
    logging.getLogger('tika').setLevel(logging.WARNING)
    TIKA_AVAILABLE = True
except ImportError:
    TIKA_AVAILABLE = False


def extract_text(file_path, logger=None):
    """
    Extract text content from a file.

    For rich document formats (PDF, Office docs, etc.) uses Apache Tika.
    Falls back to direct UTF-8 reading if Tika is unavailable or fails.

    Returns the extracted text as a string, or None on failure.
    """
    import os
    from pathlib import Path

    if not os.path.exists(file_path):
        return None

    ext = Path(file_path).suffix.lower().lstrip('.')

    if ext in TIKA_EXTENSIONS:
        return _extract_with_tika(file_path, logger)
    else:
        return _extract_as_text(file_path, logger)


def _extract_with_tika(file_path, logger=None):
    """Extract text using Apache Tika."""
    if not TIKA_AVAILABLE:
        if logger:
            logger.warning(
                f"Apache Tika not available. Install with: pip install tika  "
                f"(also requires Java). Falling back to raw text for {file_path}"
            )
        return _extract_as_text(file_path, logger)

    try:
        parsed = tika_parser.from_file(file_path)
        content = parsed.get('content')
        if content:
            return content
        if logger:
            logger.debug(f"Tika returned no content for {file_path}")
        return None

    except Exception as e:
        if logger:
            logger.debug(f"Tika extraction failed for {file_path}: {e}")
        # Fallback to raw text (may not work well for binary formats)
        return _extract_as_text(file_path, logger)


def _extract_as_text(file_path, logger=None):
    """Read file as plain UTF-8 text."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        if logger:
            logger.debug(f"Text read failed for {file_path}: {e}")
        return None
