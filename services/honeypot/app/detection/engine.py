"""
Detection Engine — Core Evaluator
Day 2: Rule-Based Attack Detection

Evaluates ALL rule categories against the combined attack surface:
  - request endpoint (URL path + query string)
  - request payload (body)
  - serialized request headers

Returns a DetectionResult dataclass with:
  status          : "malicious" | "suspicious"
  attack_type     : category string or "unknown"
  detection_score : 0.0 – 1.0
  matched_rule    : description of the first matching pattern (for logging)

Design principles:
  - Zero external I/O — purely CPU-bound, deterministic
  - Early-exit on first high-confidence match (score >= 0.90)
  - Full scan otherwise to find the highest-confidence match
  - Modular: plug in AI classifier later by replacing/augmenting this output
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from app.detection.rules import ALL_RULES, Rule


# Default result when no rule matches
_DEFAULT_SCORE: float = 0.2
_MALICIOUS_THRESHOLD: float = 0.50   # Any match at or above → "malicious"


@dataclass(slots=True)
class DetectionResult:
    status:          str   = "suspicious"
    attack_type:     str   = "unknown"
    detection_score: float = _DEFAULT_SCORE
    matched_rule:    str   = ""
    all_matches:     list  = field(default_factory=list)


def _serialize_headers(headers: dict) -> str:
    """Flatten headers dict to a single inspectable string."""
    try:
        return " ".join(f"{k}: {v}" for k, v in headers.items())
    except Exception:  # noqa: BLE001
        return ""


def analyze(
    *,
    endpoint: str,
    payload: str,
    headers: dict,
) -> DetectionResult:
    """
    Run all rules against endpoint, payload, and headers.

    Returns the highest-confidence match found, or a default suspicious
    result if nothing fires.

    Args:
        endpoint: The URL path (e.g. "/login?user=admin")
        payload:  Raw request body as a string
        headers:  Request headers dict

    Returns:
        DetectionResult
    """
    # Build combined inspection surface (endpoint + payload + headers)
    header_str    = _serialize_headers(headers)
    scan_surface  = f"{endpoint}\n{payload}\n{header_str}"

    best_match: Rule | None = None
    best_score: float       = 0.0
    all_matches: list[dict] = []

    for rule in ALL_RULES:
        m = rule["pattern"].search(scan_surface)
        if m:
            match_info = {
                "attack_type": rule["attack_type"],
                "confidence":  rule["confidence"],
                "matched_text": m.group(0)[:120],   # truncate for safety
            }
            all_matches.append(match_info)

            if rule["confidence"] > best_score:
                best_score  = rule["confidence"]
                best_match  = rule

            # Early exit on very high confidence — no need to scan further
            if best_score >= 0.98:
                break

    if best_match is None:
        # No pattern matched — determine if this looks benign or suspicious
        # Heuristic: short payloads on common API paths with no encoded chars are likely safe
        combined_len = len(endpoint) + len(payload)
        has_encoding = any(c in scan_surface for c in ['%00', '%0a', '%0d', '\\x', '\\u'])
        lower_surface = scan_surface.lower()
        looks_benign = (
            combined_len < 500
            and not has_encoding
            and not any(kw in lower_surface for kw in [
                # Original heuristic keywords
                'passwd', 'shadow', 'admin', 'root', 'shell', 'exec',
                'system(', 'eval(', 'base64', 'cmd', '<!--', 'entity',
                'doctype', '<!', 'file://', 'meta-data', '$gt', '$ne',
                '$regex', 'security-credentials', '/internal',
                # SSTI / Template Injection indicators
                '{{', '{%', '__class__', '__globals__', '__init__',
                '__builtins__', 'popen', '__import__', 'config.',
                # Log4Shell / JNDI injection
                'jndi', 'ldap://', 'rmi://', '${',
                # Obfuscated SQL / comment-stuffed
                '/**/', 'uni0n', 'sel ect', 'fr0m', 'inf0rmation',
                # Deserialization / prototype pollution
                '__proto__', 'constructor', 'rO0AB', 'aced0005',
                # SSRF additional patterns
                '169.254.169.254', 'metadata.google', 'metadata.azure',
                '127.0.0.1', '0x7f000001',
                # Header injection / request smuggling
                '\\r\\n', 'transfer-encoding', 'content-length:',
            ])
        )

        if looks_benign:
            return DetectionResult(
                status="safe",
                attack_type="none",
                detection_score=0.0,
                matched_rule="",
                all_matches=[],
            )

        return DetectionResult(
            status="suspicious",
            attack_type="unknown",
            detection_score=_DEFAULT_SCORE,
            matched_rule="",
            all_matches=[],
        )

    status = "malicious" if best_score >= _MALICIOUS_THRESHOLD else "suspicious"

    return DetectionResult(
        status=status,
        attack_type=best_match["attack_type"],
        detection_score=round(best_score, 4),
        matched_rule=best_match["pattern"].pattern[:120],
        all_matches=all_matches,
    )
