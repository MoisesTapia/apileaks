"""
modules.mcp_security — Offensive auditing of third-party MCP servers.

Exposes :class:`~modules.mcp_security.mcp_target_auditor.MCPTargetAuditor`
and :class:`~modules.mcp_security.poisoning_detector.ToolPoisoningDetector`
as the public API of this package.

Requirements: 8.1 – 8.5
"""

from modules.mcp_security.mcp_target_auditor import MCPTargetAuditor
from modules.mcp_security.poisoning_detector import ToolPoisoningDetector

__all__ = ["MCPTargetAuditor", "ToolPoisoningDetector"]
