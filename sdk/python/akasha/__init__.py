"""
Akasha — local vault SDK for AI agents.

import os
from akasha import Akasha

vault = Akasha(agent_id="support-bot-v2", api_key=os.environ["AKASHA_AGENT_KEY"])
result = vault.wrap("send_email", "send to user@example.com")
# result.clean_content  → "send to vault://abc12345"
# result.vaulted        → True

api_key is required — mint one with `akasha agent create <id>`. The daemon
refuses unauthenticated callers, so omitting it raises rather than falling back.
"""

from .client import Akasha, AkashaTransportError, GrantResult, WrapResult

__all__ = ["Akasha", "AkashaTransportError", "GrantResult", "WrapResult"]

# Integrations are optional — imported only when the relevant SDK is installed.
# from akasha.integrations import AkashaAnthropic, AkashaOpenAI
__version__ = "0.1.0"
