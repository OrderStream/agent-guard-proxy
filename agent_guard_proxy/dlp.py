"""
DLP (Data Loss Prevention) and Secret Leakage Engine for MCP Tool Calls and Responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class SecretType(str, Enum):
    OPENAI_API_KEY = "OpenAI API Key"
    ANTHROPIC_API_KEY = "Anthropic API Key"
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    GITHUB_TOKEN = "GitHub Token"
    STELLAR_SECRET_SEED = "Stellar Secret Seed (Ed25519)"
    PRIVATE_KEY = "RSA/EC/Ed25519 Private Key"
    GENERIC_BEARER = "Authorization Bearer Token"
    DATABASE_URI = "Database Connection String with Credentials"


@dataclass
class DLPViolation:
    secret_type: SecretType
    matched_snippet: str
    redacted_snippet: str
    location: str


class DLPFilter:
    """
    High-performance regex and entropy scanner preventing credential leakage in MCP traffic.
    """

    PATTERNS: Dict[SecretType, re.Pattern] = {
        SecretType.OPENAI_API_KEY: re.compile(r"\bsk-(?!ant-)[a-zA-Z0-9_-]{20,64}\b"),
        SecretType.ANTHROPIC_API_KEY: re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,80}\b"),
        SecretType.AWS_ACCESS_KEY: re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        SecretType.AWS_SECRET_KEY: re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        SecretType.GITHUB_TOKEN: re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}"),
        SecretType.STELLAR_SECRET_SEED: re.compile(r"\bS[A-Z2-7]{55}\b"),
        SecretType.PRIVATE_KEY: re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        SecretType.GENERIC_BEARER: re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{30,}"),
        SecretType.DATABASE_URI: re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+"),
    }

    def __init__(self, redact_mode: bool = True):
        self.redact_mode = redact_mode

    def scan_text(self, text: str, location: str = "payload") -> List[DLPViolation]:
        """Scans arbitrary text for secret patterns."""
        violations: List[DLPViolation] = []
        if not text:
            return violations

        for sec_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                raw = match.group(0)
                if len(raw) > 8:
                    redacted = raw[:4] + "*" * (len(raw) - 8) + raw[-4:]
                else:
                    redacted = "****"

                violations.append(
                    DLPViolation(
                        secret_type=sec_type,
                        matched_snippet=raw,
                        redacted_snippet=redacted,
                        location=location,
                    )
                )
        return violations

    def redact_text(self, text: str) -> Tuple[str, List[DLPViolation]]:
        """Redacts all discovered secrets from text."""
        violations = self.scan_text(text)
        cleaned = text
        for v in violations:
            cleaned = cleaned.replace(v.matched_snippet, v.redacted_snippet)
        return cleaned, violations

    def scan_and_sanitize_dict(self, data: any, path: str = "root") -> Tuple[any, List[DLPViolation]]:
        """Recursively scans and sanitizes nested dictionaries or lists."""
        violations: List[DLPViolation] = []

        if isinstance(data, str):
            clean_str, viols = self.redact_text(data)
            for v in viols:
                v.location = path
            return clean_str, viols

        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                cur_path = f"{path}.{k}"
                # Check key itself
                clean_k, k_viols = self.redact_text(str(k))
                clean_v, v_viols = self.scan_and_sanitize_dict(v, cur_path)
                violations.extend(k_viols)
                violations.extend(v_viols)
                new_dict[clean_k] = clean_v
            return new_dict, violations

        if isinstance(data, list):
            new_list = []
            for idx, item in enumerate(data):
                cur_path = f"{path}[{idx}]"
                clean_item, item_viols = self.scan_and_sanitize_dict(item, cur_path)
                violations.extend(item_viols)
                new_list.append(clean_item)
            return new_list, violations

        return data, violations
