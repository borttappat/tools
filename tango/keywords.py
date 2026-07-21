"""
Tango Keyword Configuration
Shared default keyword set, keyword-file parsing, per-investigation saved
keyword lists, and the interactive keyword-configuration menu used by both
local-talk (localtalk.py) and talk (smbtalk.py).
"""

from pathlib import Path

DEFAULT_KEYWORDS = [
    'password', 'passwd', 'pass', 'pwd',
    'secret', 'credential', 'cred',
    'api_key', 'apikey', 'api-key',
    'private_key', 'privatekey', 'private-key',
    'ssh_key', 'sshkey', 'ssh-key',
    'access_key', 'accesskey', 'access-key',
    'secret_key', 'secretkey', 'secret-key',
    'key', 'token', 'bearer', 'auth', 'authentication',
    'username', 'user', 'account',
    'admin', 'administrator', 'root',
    'database', 'db', 'connection', 'connectionstring',
    'dsn', 'jdbc', 'cert', 'certificate', 'pem', 'pfx', 'p12'
]


def dedupe(keywords):
    """Remove duplicates while preserving order."""
    seen = set()
    unique = []
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            unique.append(kw)
    return unique


def parse_keywords_file(path):
    """Read one keyword per line. Blank lines and '#' comments are skipped."""
    with open(path, 'r') as f:
        lines = [line.strip() for line in f]
    return [line.lower() for line in lines if line and not line.startswith('#')]


def saved_keywords_path(mode, identifier):
    """Per-investigation saved keyword list path, mirroring the index-file naming."""
    return Path(f"{mode}_keywords_{identifier}.txt")


def load_saved_keywords(mode, identifier):
    """Return the saved keyword list for this investigation, or None if none exists."""
    path = saved_keywords_path(mode, identifier)
    if not path.exists():
        return None
    return dedupe(parse_keywords_file(path))


def save_saved_keywords(mode, identifier, keywords_list):
    """Write the keyword list for this investigation, one per line, with a header."""
    path = saved_keywords_path(mode, identifier)
    with open(path, 'w') as f:
        f.write(f"# tango saved keyword list for {mode} investigation: {identifier}\n")
        for kw in keywords_list:
            f.write(f"{kw}\n")
    return path


def _print_wrapped(keywords_list, width=76, indent="  "):
    line = ""
    for kw in keywords_list:
        piece = f"{kw}, "
        if len(line) + len(piece) > width:
            print(f"{indent}{line.rstrip()}")
            line = ""
        line += piece
    if line:
        print(f"{indent}{line.rstrip(', ')}")


def _manage_saved_list(mode, identifier):
    """Sub-menu: view / add / remove / reset / save the per-investigation list."""
    saved = load_saved_keywords(mode, identifier)
    working = list(saved) if saved is not None else list(DEFAULT_KEYWORDS)
    path = saved_keywords_path(mode, identifier)

    while True:
        print(f"\nManaging saved list: {path} ({len(working)} keywords)")
        _print_wrapped(working)
        print("\n  a. Add keywords")
        print("  r. Remove keywords")
        print("  x. Reset to default keyword set")
        print("  s. Save to disk")
        print("  u. Use this list now")
        print("  b. Back to main menu")

        choice = input("\nYour choice [a/r/x/s/u/b]: ").strip().lower()

        if choice == 'a':
            raw = input("Keywords to add (comma-separated): ").strip()
            if raw:
                working = dedupe(working + [kw.strip().lower() for kw in raw.split(',')])
        elif choice == 'r':
            raw = input("Keywords to remove (comma-separated): ").strip()
            if raw:
                to_remove = {kw.strip().lower() for kw in raw.split(',')}
                working = [kw for kw in working if kw not in to_remove]
        elif choice == 'x':
            working = list(DEFAULT_KEYWORDS)
        elif choice == 's':
            save_saved_keywords(mode, identifier, working)
            print(f"Saved {len(working)} keywords to {path}")
        elif choice == 'u':
            return working
        elif choice == 'b':
            return None
        else:
            print("  Invalid choice.")


def interactive_keyword_menu(mode, identifier, logger=None):
    """Interactive keyword configuration. mode is 'local' or 'smb'."""
    saved = load_saved_keywords(mode, identifier)
    path = saved_keywords_path(mode, identifier)

    while True:
        print("\n" + "=" * 80)
        print("Keyword Search Configuration")
        print("=" * 80)
        print(f"\nDefault keyword set ({len(DEFAULT_KEYWORDS)} keywords):")
        _print_wrapped(DEFAULT_KEYWORDS)
        if saved is not None:
            print(f"\nSaved list found for this investigation: {path} ({len(saved)} keywords)")

        print("\n  1. Use default keyword set as-is")
        print("  2. Use default set + append extra keywords")
        print("  3. Enter custom keywords manually (only these, no defaults)")
        print("  4. Load keywords from a file (only these, no defaults)")
        if saved is not None:
            print(f"  5. Use saved list from {path}")
        print("  6. Manage saved keyword list (view / add / remove / reset)")

        choice = input("\nYour choice: ").strip()

        base = None
        try:
            if choice == '1':
                base = list(DEFAULT_KEYWORDS)
            elif choice == '2':
                extra = input("Add extra keywords (comma-separated): ").strip()
                extra_kw = [kw.strip().lower() for kw in extra.split(',')] if extra else []
                base = dedupe(DEFAULT_KEYWORDS + extra_kw)
            elif choice == '3':
                raw = input("Enter keywords (comma-separated): ").strip()
                if raw:
                    base = dedupe([kw.strip().lower() for kw in raw.split(',')])
            elif choice == '4':
                file_path = input("Keywords file path: ").strip()
                try:
                    base = dedupe(parse_keywords_file(file_path))
                except FileNotFoundError:
                    print(f"  File not found: {file_path}")
                    continue
            elif choice == '5' and saved is not None:
                base = list(saved)
            elif choice == '6':
                managed = _manage_saved_list(mode, identifier)
                if managed is None:
                    saved = load_saved_keywords(mode, identifier)
                    continue
                base = managed
            else:
                print("  Invalid choice.")
                continue
        except KeyboardInterrupt:
            print("\nAborted.")
            return []

        if not base:
            print("  No keywords selected.")
            continue

        try:
            extra = input("Add extra keywords for this run only (won't be saved), "
                           "comma-separated, or Enter to skip: ").strip()
            if extra:
                base = dedupe(base + [kw.strip().lower() for kw in extra.split(',')])

            save_choice = input(f"Save this list to {path} for future runs on this "
                                 f"investigation? [y/N]: ").strip().lower()
            if save_choice in ('y', 'yes'):
                save_saved_keywords(mode, identifier, base)
                if logger:
                    logger.info(f"Saved {len(base)} keywords to {path}")

            confirm = input(f"Proceed with {len(base)} keywords? [Y/n]: ").strip().lower()
            if confirm in ('', 'y', 'yes'):
                return base
        except KeyboardInterrupt:
            print("\nAborted.")
            return []
