"""
Tango Pause & Checkpoint Support
Shared by smbtalk.py (talk) and localtalk.py (local-talk): lets a long-running
download/search loop be paused with Ctrl+C and resumed later, either in the
same run or by rerunning the same command after the process was killed.
"""

import json
import os
import signal
import sys


class PauseHandler:
    """Installs a SIGINT handler that pauses instead of crashing.

    First Ctrl+C sets a flag; the caller's loop checks it at a safe point
    (after a file is done) via .check(). A second Ctrl+C while the
    resume/quit prompt from .check() is on screen force-exits immediately
    instead of just re-arming the pause.
    """

    def __init__(self):
        self._pause_requested = False
        self._at_prompt = False
        self._old_handler = signal.signal(signal.SIGINT, self._handle)

    def _handle(self, signum, frame):
        if self._at_prompt:
            print("\nForce quit.")
            sys.exit(130)
        self._pause_requested = True

    def check(self, progress_note=""):
        """Call at a safe point in a loop. Returns 'resume' or 'quit'."""
        if not self._pause_requested:
            return "resume"

        self._pause_requested = False
        self._at_prompt = True
        try:
            print(f"\nPaused. {progress_note}")
            while True:
                try:
                    choice = input("[r]esume, [q]uit and save progress: ").strip().lower()
                except EOFError:
                    print("\nNo input available, quitting and saving progress.")
                    return "quit"
                if choice in ("r", "resume", ""):
                    print("Resuming...")
                    return "resume"
                if choice in ("q", "quit"):
                    return "quit"
        finally:
            self._at_prompt = False

    def restore(self):
        """Reinstall the previous SIGINT handler."""
        signal.signal(signal.SIGINT, self._old_handler)


def save_checkpoint(path, data):
    """Atomically write a checkpoint JSON file."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp_path, path)


def load_checkpoint(path, logger=None):
    """Load a checkpoint JSON file. Returns None if missing or corrupt."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        if logger:
            logger.warning(f"Checkpoint at {path} is unreadable ({e}), starting fresh.")
        return None


def remove_checkpoint(path):
    """Delete a checkpoint file if it exists."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
