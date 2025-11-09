#!/usr/bin/env python3
"""
SMBHound - SMB Share Reconnaissance Tool
Main wrapper script implementing the two-phase architecture
"""

import argparse
import sys
import os
import json
from pathlib import Path

VERSION = "1.0.0"

def check_index_exists(target_ip):
    """Check if index file exists for target"""
    index_file = f"smb_index_{target_ip}.json"
    return os.path.exists(index_file)

def main():
    parser = argparse.ArgumentParser(
        description="SMBHound - Systematic SMB share reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect phase (walk if no index, talk if index exists)
  smbhound -t 10.0.0.5 -u admin -p pass

  # Explicit walk phase
  smbhound walk -t 10.0.0.5 -u admin -p pass

  # Explicit talk phase
  smbhound talk --filetypes txt,ini

  # Combined auto mode
  smbhound -t 10.0.0.5 -u admin -p pass --filetypes txt,ini --keywords creds.txt
        """
    )
    
    # Add subparsers for walk and talk commands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    
    # Walk command
    walk_parser = subparsers.add_parser('walk', parents=[common_parser], 
                                       help='Index SMB shares (Phase 1)')
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
    
    # Talk command
    talk_parser = subparsers.add_parser('talk', parents=[common_parser],
                                       help='Download and analyze files (Phase 2)')
    talk_parser.add_argument('--filetypes',
                           help='Comma-separated file extensions (e.g., txt,ini,xml)')
    talk_parser.add_argument('--keywords',
                           help='Path to keywords file (one keyword per line)')
    talk_parser.add_argument('--keywords-inline',
                           help='Comma-separated keywords inline')
    talk_parser.add_argument('--override-filesize',
                           help='Override 50MB limit (in MB, or "unlimited")')
    talk_parser.add_argument('--config',
                           help='Load configuration from file')
    
    # Global arguments (for auto-detect mode)
    parser.add_argument('-t', '--target',
                       help='Target SMB server IP address')
    parser.add_argument('-u', '--username',
                       help='Username for authentication')
    parser.add_argument('-p', '--password',
                       help='Password for authentication')
    parser.add_argument('-d', '--domain', default='WORKGROUP',
                       help='Domain name (default: WORKGROUP)')
    parser.add_argument('--dc-ip', dest='dc_ip',
                       help='Domain controller IP address')
    parser.add_argument('--filetypes',
                       help='Comma-separated file extensions (triggers auto mode)')
    parser.add_argument('--keywords',
                       help='Path to keywords file (triggers auto mode)')
    parser.add_argument('--keywords-inline',
                       help='Comma-separated keywords inline (triggers auto mode)')
    parser.add_argument('--override-filesize',
                       help='Override 50MB limit (in MB, or "unlimited")')
    parser.add_argument('--version', action='version', version=f'SMBHound {VERSION}')
    
    args = parser.parse_args()
    
    # Handle no arguments or explicit command behavior
    if args.command is None:
        # Auto-detect mode
        if not args.target:
            parser.error("Target (-t) is required for auto-detect mode")
        
        # Check if this is combined mode (has analysis options)
        is_combined_mode = any([args.filetypes, args.keywords, args.keywords_inline])
        
        if is_combined_mode:
            # Combined mode: run both phases automatically
            print(f"SMBHound v{VERSION} - Combined Mode")
            print(f"Target: {args.target}")
            print("Running both walk and talk phases...")
            
            # Run walk phase
            if not check_index_exists(args.target):
                print("No index found. Running walk phase first...")
                run_walk_phase(args)
            else:
                print("Index exists. Skipping walk phase.")
            
            # Run talk phase
            print("Running talk phase...")
            run_talk_phase(args)
        else:
            # Auto-detect based on index existence
            if check_index_exists(args.target):
                print(f"SMBHound v{VERSION} - Auto-detected: Talk Phase")
                print(f"Index found for {args.target}. Running talk phase...")
                run_talk_phase(args)
            else:
                print(f"SMBHound v{VERSION} - Auto-detected: Walk Phase")
                print(f"No index found for {args.target}. Running walk phase...")
                run_walk_phase(args)
    
    elif args.command == 'walk':
        print(f"SMBHound v{VERSION} - Walk Phase")
        run_walk_phase(args)
    
    elif args.command == 'talk':
        print(f"SMBHound v{VERSION} - Talk Phase")
        run_talk_phase(args)

def run_walk_phase(args):
    """Execute the walk phase"""
    try:
        # Add current directory to path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from smbwalk import SMBWalker
        
        walker = SMBWalker(args.target, args.username, args.password, 
                          args.domain, args.dc_ip)
        result = walker.walk()
        
        if result:
            print("Walk phase completed successfully.")
        else:
            print("Walk phase failed.")
            sys.exit(1)
            
    except ImportError as e:
        print(f"Error: Failed to import smbwalk module: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Walk phase failed: {e}")
        sys.exit(1)

def run_talk_phase(args):
    """Execute the talk phase"""
    try:
        # Add current directory to path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from smbtalk import SMBTalker
        
        talker = SMBTalker(args.target if hasattr(args, 'target') and args.target else None,
                          args.filetypes, args.keywords, args.keywords_inline, 
                          args.override_filesize)
        result = talker.talk()
        
        if result:
            print("Talk phase completed successfully.")
        else:
            print("Talk phase failed.")
            sys.exit(1)
            
    except ImportError as e:
        print(f"Error: Failed to import smbtalk module: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Talk phase failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()