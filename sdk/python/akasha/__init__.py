"""
Akasha — local vault SDK for AI agents.

from akasha import Akasha

vault = Akasha(agent_id="support-bot-v2")
result = vault.wrap("send_email", "send to user@example.com")
# result.clean_content  → "send to vault://abc12345"
# result.vaulted        → True
"""

from .client import Akasha, WrapResult, GrantResult

__all__ = ["Akasha", "WrapResult", "GrantResult"]

# Integrations are optional — imported only when the relevant SDK is installed.
# from akasha.integrations import AkashaAnthropic, AkashaOpenAI
__version__ = "0.1.0"
