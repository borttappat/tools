"""
Tango Metadata Extractor
Pulls embedded file metadata (authorship, GPS, software, revision history,
timestamps, etc.) via ExifTool, which covers images, PDFs, Office docs,
audio/video and thousands of other formats in one pass. Falls back to
Apache Tika's metadata output (already available for text extraction) for
the document types Tika parses, if ExifTool isn't installed.
"""

import atexit
import logging

try:
    import exiftool
    EXIFTOOL_AVAILABLE = True
except ImportError:
    EXIFTOOL_AVAILABLE = False

try:
    from tika import parser as tika_parser
    logging.getLogger('tika').setLevel(logging.WARNING)
    TIKA_AVAILABLE = True
except ImportError:
    TIKA_AVAILABLE = False

# ExifTool bookkeeping tags that are just filesystem/tool info, not
# meaningful document metadata - dropped from the output.
_NOISE_PREFIXES = ('ExifTool:', 'File:File', 'SourceFile')

# Tags worth calling out explicitly in reports: anything hinting at a
# person, organization, device, or location behind the file.
NOTABLE_TAGS = {
    'Author', 'Creator', 'LastModifiedBy', 'Company', 'Manager', 'Owner',
    'Software', 'CreatorTool', 'Producer', 'Application', 'HostComputer',
    'Make', 'Model', 'GPSLatitude', 'GPSLongitude', 'GPSPosition',
    'Title', 'Subject', 'RevisionNumber', 'TotalEditTime', 'HyperlinkBase',
    'LastPrinted', 'CreateDate', 'ModifyDate', 'UserComment', 'Comment',
}

_exiftool_helper = None


def _get_exiftool_helper():
    global _exiftool_helper
    if _exiftool_helper is None:
        _exiftool_helper = exiftool.ExifToolHelper()
        atexit.register(_exiftool_helper.terminate)
    return _exiftool_helper


def extract_metadata(file_path, logger=None):
    """
    Extract embedded metadata from a file.

    Returns a flat dict of tag -> value, or None if nothing could be read.
    """
    if EXIFTOOL_AVAILABLE:
        try:
            helper = _get_exiftool_helper()
            results = helper.get_metadata([file_path])
            if results:
                tags = results[0]
                cleaned = {
                    k: v for k, v in tags.items()
                    if not any(k.startswith(p) for p in _NOISE_PREFIXES)
                }
                if cleaned:
                    return cleaned
        except Exception as e:
            if logger:
                logger.debug(f"ExifTool extraction failed for {file_path}: {e}")
    elif logger:
        logger.debug(
            "ExifTool not available (pip install pyexiftool, requires the "
            "'exiftool' binary). Falling back to Tika metadata where possible."
        )

    return _extract_with_tika(file_path, logger)


def _extract_with_tika(file_path, logger=None):
    if not TIKA_AVAILABLE:
        return None
    try:
        parsed = tika_parser.from_file(file_path)
        metadata = parsed.get('metadata')
        if metadata:
            return metadata
    except Exception as e:
        if logger:
            logger.debug(f"Tika metadata extraction failed for {file_path}: {e}")
    return None


def notable_fields(metadata):
    """Pull out the subset of tags most relevant to recon/attribution."""
    if not metadata:
        return {}
    found = {}
    for tag, value in metadata.items():
        bare_tag = tag.split(':', 1)[-1]
        if bare_tag in NOTABLE_TAGS and bare_tag not in found:
            found[bare_tag] = value
    return found
