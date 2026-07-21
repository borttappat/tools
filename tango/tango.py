#!/usr/bin/env python3
"""
Tango - File Share Reconnaissance & Analysis Tool

Modes:
  SMB mode  - enumerate and analyze SMB shares (requires credentials)
  Local mode - crawl and analyze local directory dumps (no authentication)
"""

import argparse
import sys
import os
import json
from pathlib import Path

VERSION = "1.1.0"


def main():
    parser = argparse.ArgumentParser(
        description="Tango - File share reconnaissance and keyword analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SMB: index a share
  tango walk -t 10.0.0.5 -u admin -p pass

  # SMB: download and search indexed files
  tango talk --filetypes txt,ini,xml
  tango talk --filetypes pdf,docx,xlsx      # uses Apache Tika

  # SMB: combined (walk then talk)
  tango -t 10.0.0.5 -u admin -p pass --filetypes txt,ini --keywords creds.txt

  # Local: index a file server dump folder
  tango local-walk /mnt/fileserver/dump

  # Local: search indexed local files
  tango local-talk /mnt/fileserver/dump --filetypes pdf,docx,xlsx,txt
  tango local-talk /mnt/fileserver/dump --keywords-inline password,secret,token
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # ------------------------------------------------------------------
    # walk subcommand (SMB)
    # ------------------------------------------------------------------
    walk_parser = subparsers.add_parser('walk', help='Index an SMB share (Phase 1)')
    walk_parser.add_argument('-t', '--target', required=True,
                             help='Target SMB server IP address')
    walk_parser.add_argument('-u', '--username', required=True,
                             help='Username for authentication')
    walk_parser.add_argument('-p', '--password', required=True,
                             help='Password for authentication')
    walk_parser.add_argument('-d', '--domain', default='WORKGROUP',
                             help='Domain name (default: WORKGROUP)')
    walk_parser.add_argument('--dc-ip', dest='dc_ip',
                             help='Domain controller IP address')

    # ------------------------------------------------------------------
    # talk subcommand (SMB)
    # ------------------------------------------------------------------
    talk_parser = subparsers.add_parser('talk', help='Download and analyze SMB files (Phase 2)')
    talk_parser.add_argument('--filetypes',
                             help='Comma-separated extensions to process (e.g. txt,ini,pdf,docx)')
    talk_parser.add_argument('--keywords',
                             help='Path to keywords file (one per line)')
    talk_parser.add_argument('--keywords-inline',
                             help='Comma-separated keywords')
    talk_parser.add_argument('--keywords-saved', action='store_true',
                             help='Load the saved per-investigation keyword list (skips the interactive menu)')
    talk_parser.add_argument('--override-filesize',
                             help='Override 50MB limit (in MB, or "unlimited")')

    # ------------------------------------------------------------------
    # local-walk subcommand
    # ------------------------------------------------------------------
    lw_parser = subparsers.add_parser('local-walk',
                                      help='Index a local directory tree (no auth required)')
    lw_parser.add_argument('path', help='Path to the local directory to index')

    # ------------------------------------------------------------------
    # local-talk subcommand
    # ------------------------------------------------------------------
    lt_parser = subparsers.add_parser('local-talk',
                                      help='Search an indexed local directory for keywords')
    lt_parser.add_argument('path', help='Path to the local directory (must match local-walk path)')
    lt_parser.add_argument('--filetypes',
                           help='Comma-separated extensions to search (e.g. pdf,docx,txt,xlsx)')
    lt_parser.add_argument('--keywords',
                           help='Path to keywords file')
    lt_parser.add_argument('--keywords-inline',
                           help='Comma-separated keywords')
    lt_parser.add_argument('--keywords-saved', action='store_true',
                           help='Load the saved per-investigation keyword list (skips the interactive menu)')
    lt_parser.add_argument('--override-filesize',
                           help='Override 50MB per-file limit (in MB, or "unlimited")')

    # ------------------------------------------------------------------
    # Global args for SMB auto-detect mode
    # ------------------------------------------------------------------
    parser.add_argument('-t', '--target', help='SMB target IP (auto-detect mode)')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-d', '--domain', default='WORKGROUP', help='Domain')
    parser.add_argument('--dc-ip', dest='dc_ip', help='Domain controller IP')
    parser.add_argument('--filetypes', help='File types for combined auto mode')
    parser.add_argument('--keywords', help='Keywords file for combined auto mode')
    parser.add_argument('--keywords-inline', help='Inline keywords for combined auto mode')
    parser.add_argument('--keywords-saved', action='store_true',
                        help='Load the saved per-investigation keyword list for combined auto mode')
    parser.add_argument('--override-filesize', help='Override file size limit')
    parser.add_argument('--version', action='version', version=f'Tango {VERSION}')

    args = parser.parse_args()

    if args.command is None:
        # Auto-detect SMB mode
        if not args.target:
            parser.print_help()
            sys.exit(1)

        is_combined = any([args.filetypes, args.keywords, args.keywords_inline])

        if is_combined:
            print(f"Tango v{VERSION} - SMB Combined Mode")
            print(f"Target: {args.target}")
            if not _check_smb_index(args.target):
                print("No index found. Running SMB walk first...")
                _run_walk(args)
            else:
                print("Index found. Skipping walk.")
            print("Running SMB talk...")
            _run_talk(args)
        else:
            if _check_smb_index(args.target):
                print(f"Tango v{VERSION} - Auto-detected: SMB Talk Phase")
                _run_talk(args)
            else:
                print(f"Tango v{VERSION} - Auto-detected: SMB Walk Phase")
                if not args.username or not args.password:
                    parser.error("Username (-u) and password (-p) are required for walk phase")
                _run_walk(args)

    elif args.command == 'walk':
        print(f"Tango v{VERSION} - SMB Walk Phase")
        _run_walk(args)

    elif args.command == 'talk':
        print(f"Tango v{VERSION} - SMB Talk Phase")
        _run_talk(args)

    elif args.command == 'local-walk':
        print(f"Tango v{VERSION} - Local Walk Phase")
        _run_local_walk(args)

    elif args.command == 'local-talk':
        print(f"Tango v{VERSION} - Local Talk Phase")
        _run_local_talk(args)


# -----------------------------------------------------------------------
# SMB helpers
# -----------------------------------------------------------------------

def _check_smb_index(target_ip):
    return os.path.exists(f"smb_index_{target_ip}.json")


def _run_walk(args):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from smbwalk import SMBWalker

        walker = SMBWalker(args.target, args.username, args.password,
                           args.domain, getattr(args, 'dc_ip', None))
        if not walker.walk():
            sys.exit(1)

    except ImportError as e:
        print(f"Error: Failed to import smbwalk: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Walk phase failed: {e}")
        sys.exit(1)


def _run_talk(args):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from smbtalk import SMBTalker

        target = getattr(args, 'target', None)
        talker = SMBTalker(
            target_ip=target,
            filetypes=getattr(args, 'filetypes', None),
            keywords_file=getattr(args, 'keywords', None),
            keywords_inline=getattr(args, 'keywords_inline', None),
            keywords_saved=getattr(args, 'keywords_saved', False),
            override_filesize=getattr(args, 'override_filesize', None)
        )
        if not talker.talk():
            sys.exit(1)

    except ImportError as e:
        print(f"Error: Failed to import smbtalk: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Talk phase failed: {e}")
        sys.exit(1)


# -----------------------------------------------------------------------
# Local helpers
# -----------------------------------------------------------------------

def _run_local_walk(args):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from localwalk import LocalWalker

        walker = LocalWalker(args.path)
        if not walker.walk():
            sys.exit(1)

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ImportError as e:
        print(f"Error: Failed to import localwalk: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Local walk failed: {e}")
        sys.exit(1)


def _run_local_talk(args):
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from localtalk import LocalAnalyzer

        analyzer = LocalAnalyzer(
            root_path=args.path,
            filetypes=getattr(args, 'filetypes', None),
            keywords_file=getattr(args, 'keywords', None),
            keywords_inline=getattr(args, 'keywords_inline', None),
            keywords_saved=getattr(args, 'keywords_saved', False),
            override_filesize=getattr(args, 'override_filesize', None)
        )
        if not analyzer.analyze():
            sys.exit(1)

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ImportError as e:
        print(f"Error: Failed to import localtalk: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Local talk failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
