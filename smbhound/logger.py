"""
SMBHound Logging System
Centralized logging for all phases
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init()

class SMBHoundLogger:
    def __init__(self, target_ip, phase="smbhound"):
        self.target_ip = target_ip
        self.phase = phase
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_filename = f"smbhound_{target_ip}_{timestamp}.log"
        
        # Create logger
        self.logger = logging.getLogger('smbhound')
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
        
        # Log session start
        self.info("=" * 60)
        self.info("SMBHound Session Start")
        self.info("=" * 60)
        self.info(f"Version: 1.0.0")
        self.info(f"Phase: {phase.upper()}")
        self.info(f"Target: {target_ip}")
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
        # Log to file as INFO
        self.logger.info(f"[MATCH] {message}")
        # Print to console with highlighting
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
        # Add color based on level
        color = self.COLORS.get(record.levelname, Fore.WHITE)
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Special handling for different message types
        if record.levelname == 'INFO':
            if record.getMessage().startswith('[DOWNLOAD]'):
                return f"{Fore.BLUE}[{timestamp}] {record.getMessage()}{Style.RESET_ALL}"
            elif record.getMessage().startswith('[SEARCH]'):
                return f"{Fore.MAGENTA}[{timestamp}] {record.getMessage()}{Style.RESET_ALL}"
            elif record.getMessage().startswith('[COMPLETE]'):
                return f"{Fore.GREEN}[{timestamp}] {record.getMessage()}{Style.RESET_ALL}"
            elif record.getMessage().startswith('Progress:'):
                return f"{Fore.CYAN}[{timestamp}] {record.getMessage()}{Style.RESET_ALL}"
            else:
                return f"[{timestamp}] {record.getMessage()}"
        
        return f"{color}[{timestamp}] [{record.levelname}]{Style.RESET_ALL} {record.getMessage()}"

def create_logger(target_ip, phase="smbhound"):
    """Factory function to create a logger"""
    return SMBHoundLogger(target_ip, phase)