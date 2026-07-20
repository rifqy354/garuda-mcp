"""Burp Suite integration module for BugBounty MCP."""

from .burp import BurpTool, BurpClient, BurpAPIError

__all__ = ["BurpTool", "BurpClient", "BurpAPIError"]
