"""
Akasha LLM integrations.

Drop-in wrappers for popular LLM clients that add automatic vault interception:

    # Anthropic (Claude)
    from akasha.integrations.anthropic import AkashaAnthropic
    client = AkashaAnthropic(agent_id="my-agent", api_key="agt_...")

    # OpenAI / GPT
    from akasha.integrations.openai_compat import AkashaOpenAI
    client = AkashaOpenAI(agent_id="my-agent", api_key="agt_...")

    # Ollama (local)
    client = AkashaOpenAI(agent_id="my-agent", api_key="agt_...",
                          base_url="http://localhost:11434/v1", llm_api_key="ollama")

    # LM Studio (local)
    client = AkashaOpenAI(agent_id="my-agent", api_key="agt_...",
                          base_url="http://localhost:1234/v1", llm_api_key="lm-studio")

    # LiteLLM proxy
    client = AkashaOpenAI(agent_id="my-agent", api_key="agt_...",
                          base_url="http://localhost:8000/v1", llm_api_key="litellm")

What gets intercepted automatically:
  - Outbound messages: scanned for sensitive content → vaulted → tokens sent to LLM
  - Tool call arguments: vault:// tokens resolved before tool execution
  - Tool results: scanned for new sensitive content → vaulted → tokens sent back to LLM
  - Everything: logged to the Akasha audit trail with full provenance
"""

from .anthropic import AkashaAnthropic
from .openai_compat import AkashaOpenAI
from .langchain import AkashaCallback

__all__ = ["AkashaAnthropic", "AkashaOpenAI", "AkashaCallback"]
