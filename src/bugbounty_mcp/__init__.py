# BugBounty MCP Server

"""A modern, modular MCP server for bug bounty hunting and security research."""

__version__ = "0.1.0"
__author__ = "Your Name"
__license__ = "MIT"

from .config import Settings
from .server import BugBountyMCP

__all__ = ["Settings", "BugBountyMCP"]
