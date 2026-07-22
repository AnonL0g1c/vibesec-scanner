from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    recommendation: str
    extensions: tuple[str, ...] = ()


def _rx(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


RULES = (
    Rule("SEC001", "Private key committed", "critical", _rx(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Revoke/rotate the key and load it from a secret manager."),
    Rule("SEC002", "Likely API token committed", "high", _rx(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "Revoke the token and inject it through environment variables or a secret manager."),
    Rule("AWS001", "AWS access key ID exposed", "critical", _rx(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"), "Disable or delete the credential in AWS IAM, review its activity, and replace it with a scoped role or secret manager reference."),
    Rule("AWS002", "AWS secret access key exposed", "critical", _rx(r"(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?(?:\s*(?:#.*)?)?$"), "Disable or delete the paired AWS credential, review CloudTrail activity, and store the replacement outside source control."),
    Rule("INJ001", "Shell command execution", "high", _rx(r"\b(?:exec|execSync|system|popen|subprocess\.(?:run|call|Popen))\s*\("), "Avoid shell execution; use allowlisted arguments and APIs that do not invoke a shell."),
    Rule("INJ002", "Potential SQL string interpolation", "high", _rx(r"(?:SELECT|INSERT|UPDATE|DELETE).{0,120}(?:\$\{|\+\s*\w+|%s|\.format\()"), "Use parameterized queries; never concatenate user-controlled values into SQL."),
    Rule("XSS001", "Unsafe HTML rendering", "high", _rx(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|\|\s*safe\b)"), "Render text safely or sanitize untrusted HTML with a maintained allowlist sanitizer."),
    Rule("CFG001", "Permissive CORS", "medium", _rx(r"(?:allow_origins\s*=\s*\[?['\"]\*|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*)"), "Allow only the exact trusted origins and review credential handling."),
    Rule("AUTH001", "Weak hard-coded JWT secret", "high", _rx(r"(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"](?:secret|password|changeme|dev|test)['\"]"), "Generate a strong secret, store it outside source control, and rotate existing tokens."),
    Rule("CFG002", "Debug mode enabled", "medium", _rx(r"\bdebug\s*[:=]\s*(?:true|1)\b"), "Disable debug mode in production and prevent verbose error disclosure."),
)
