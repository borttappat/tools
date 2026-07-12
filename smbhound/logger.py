"""
Tango Logging System
Centralized logging for all phases
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init()

class TangoLogger:
    def __init__(self, identifier, phase="tango"):
        self.identifier = identifier
        self.phase = phase
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_filename = f"tango_{identifier}_{timestamp}.log"

        # Create logger
        self.logger = logging.getLogger(f'tango.{identifier}.{phase}')
        self.logger.setLevel(logging.DEBUG)

        # Clear any existing handlers
        self.logger.handlers.clear()

        # File handler
        file_handler = logging.FileHandler(self.log_filename)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter()
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        self.info("=" * 60)
        self.info("Tango Session Start")
        self.info("=" * 60)
        self.info(f"Version: 1.1.0")
        self.info(f"Phase: {phase.upper()}")
        self.info(f"Target: {identifier}")
        self.info(f"Log file: {self.log_filename}")
        self.info("=" * 60)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

    def match(self, message):
        """Special log level for keyword matches"""
        self.logger.info(f"[MATCH] {message}")
        print(f"{Fore.GREEN}[MATCH]{Style.RESET_ALL} {message}")

    def session_end(self, duration=None):
        """Log session end"""
        self.info("=" * 60)
        if duration:
            self.info(f"Session completed in {duration}")
        self.info("Session End")
        self.info("=" * 60)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.WHITE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')

        if record.levelname == 'INFO':
            msg = record.getMessage()
            if msg.startswith('[DOWNLOAD]'):
                return f"{Fore.BLUE}[{timestamp}] {msg}{Style.RESET_ALL}"
            elif msg.startswith('[SEARCH]'):
                return f"{Fore.MAGENTA}[{timestamp}] {msg}{Style.RESET_ALL}"
            elif msg.startswith('[COMPLETE]'):
                return f"{Fore.GREEN}[{timestamp}] {msg}{Style.RESET_ALL}"
            elif msg.startswith('Progress:'):
                return f"{Fore.CYAN}[{timestamp}] {msg}{Style.RESET_ALL}"
            else:
                return f"[{timestamp}] {msg}"

        return f"{color}[{timestamp}] [{record.levelname}]{Style.RESET_ALL} {record.getMessage()}"


def create_logger(identifier, phase="tango"):
    """Factory function to create a logger"""
    return TangoLogger(identifier, phase)
