"""
Generator Client (LLM Integration)
"""

import httpx
import logging
import os
from app.prompt_builder import build_prompt

logger = logging.getLogger("response_generator")

# Local Ollama endpoint
LLM_URL = os.environ.get("LLM_URL", "http://host.docker.internal:11434/api/generate")
# Default model to phi3.5
MODEL_NAME = os.environ.get("MODEL_NAME", "phi3:mini")

async def generate_llm_response(payload: str, endpoint: str, method: str, attack_type: str, strategy: str = "", attacker_type: str = "unknown", attack_pattern: str = "none") -> tuple[str, str]:
    prompt = build_prompt(payload, endpoint, method, attack_type, strategy, attacker_type, attack_pattern)
    
    # Try to map to an internal response type indicator
    if "SQL" in attack_type:
        res_type = "sql_result"
    elif "Command" in attack_type or "File" in attack_type:
        res_type = "system_file"
    elif "Auth" in attack_type:
        res_type = "auth_response"
    else:
        res_type = "generic_error"

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                LLM_URL,
                json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.5, "num_predict": 800}
                }
            )
            resp.raise_for_status()
            data = resp.json()
            llm_text = data.get("response", "").strip()
            # Failsafe if empty
            if not llm_text:
                raise ValueError("Empty response from Ollama")
            return llm_text, res_type
            
    except Exception as exc:
        logger.error(f"LLM generation failed: {exc}", extra={"event": "llm_error"})
        # Fallback dummy responses
        fallback = f"Vulnerable System Error: Exception evaluating {payload}"
        if res_type == "sql_result":
            fallback = "SQL Error: near 'UNION': syntax error"
        elif res_type == "system_file":
            fallback = "cat: /etc/shadow: Permission denied"
            
        return fallback, "fallback_error"
