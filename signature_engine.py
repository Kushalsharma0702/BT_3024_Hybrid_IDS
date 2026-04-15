"""
signature_engine.py — Regex and behavioral signature detection engine.

Detection categories:
  - SQL Injection (payload inspection)
  - Cross-Site Scripting / XSS
  - Command Injection
  - Port Scanning (time-window behavioral)
  - Suspicious User-Agent strings
  - Known malicious payload keywords

Design principles:
  - All regexes are pre-compiled at instantiation (zero per-packet compilation)
  - Pattern lists are externally configurable
  - Port scan detection uses an in-memory sliding window per source IP
  - Each match returns a structured result with confidence and evidence
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Pattern, Tuple

from ids_core.config import SignatureConfig

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Default pattern libraries
# ─────────────────────────────────────────────────────────────────────────────

_SQLI_PATTERNS: List[str] = [
    r"(?i)(\bUNION\b.{0,40}\bSELECT\b)",
    r"(?i)(\bSELECT\b.{0,40}\bFROM\b)",
    r"(?i)(\bDROP\b.{0,20}\bTABLE\b)",
    r"(?i)(\bINSERT\b.{0,20}\bINTO\b)",
    r"(?i)(--|;|\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)",
    r"(?i)(\bEXEC\b\s*\(|\bEXECUTE\b\s*\()",
    r"(?i)(SLEEP\s*\(\d+\)|BENCHMARK\s*\(\d+)",
    r"(?i)(INFORMATION_SCHEMA|SYS\.TABLES|SYSOBJECTS)",
    r"'[\s]*OR[\s]*'[\w]+'='[\w]+",    # ' OR 'x'='x
]

_XSS_PATTERNS: List[str] = [
    r"(?i)<script[\s>]",
    r"(?i)</script>",
    r"(?i)javascript\s*:",
    r"(?i)on(load|error|click|mouse\w+|focus|blur|key\w+)\s*=",
    r"(?i)<iframe[\s>]",
    r"(?i)document\.(cookie|write|location)",
    r"(?i)eval\s*\(",
    r"(?i)alert\s*\(",
    r"(?i)<img[^>]+src\s*=\s*['\"]?\s*javascript",
    r"(?i)expression\s*\(",
]

_CMDI_PATTERNS: List[str] = [
    r"(?i)(;|\||&&|\$\(|`)\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby|id|whoami|uname)",
    r"(?i)(\.\./){2,}",                            # path traversal
    r"(?i)/etc/(passwd|shadow|hosts|crontab)",
    r"(?i)(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)",
    r"(?i)(wget|curl)\s+https?://",
    r"(?i)>>\s*/?(etc|tmp|var|proc)/",
    r"(?i)\$\{IFS\}",                              # IFS evasion
]

_MALICIOUS_KEYWORDS: List[str] = [
    r"(?i)\bmetasploit\b",
    r"(?i)\bmeterpreter\b",
    r"(?i)\bcobalt.?strike\b",
    r"(?i)\bmirai\b",
    r"(?i)\bwannacry\b",
    r"(?i)\bsqlmap\b",
    r"(?i)\bnikto\b",
    r"(?i)\bnmap\b",
    r"(?i)\bhydra\b",
    r"(?i)\baircrack\b",
]

_SUSPICIOUS_UA_PATTERNS: List[str] = [
    r"(?i)sqlmap",
    r"(?i)nikto",
    r"(?i)nmap",
    r"(?i)masscan",
    r"(?i)python-requests/[01]\.",    # old versions often used in scripts
    r"(?i)go-http-client",
    r"(?i)dirbuster",
    r"(?i)gobuster",
    r"(?i)burpsuite",
    r"(?i)hydra",
    r"(?i)havij",
    r"(?i)libwww-perl",
    r"(?i)zgrab",
    r"(?i)masscan",
]


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SignatureMatch:
    """Result of a signature check."""
    matched: bool
    category: str           # "sql_injection" | "xss" | "command_injection" | etc.
    confidence: float
    evidence: str           # matched pattern or behavioral note
    pattern_hit: str = ""


@dataclass
class _PortScanState:
    """Tracks per-source port access behavior."""
    ports_contacted: Deque[Tuple[float, int]] = field(default_factory=deque)


# ─────────────────────────────────────────────────────────────────────────────
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

class SignatureEngine:
    """
    Pre-compiled signature library for real-time packet inspection.

    Instantiate once; call `inspect()` per packet.
    """

    def __init__(
        self,
        config: SignatureConfig,
        extra_sqli: Optional[List[str]] = None,
        extra_xss: Optional[List[str]] = None,
        extra_cmdi: Optional[List[str]] = None,
        extra_keywords: Optional[List[str]] = None,
        extra_ua: Optional[List[str]] = None,
    ) -> None:
        self._cfg = config

        # Pre-compile all patterns
        self._sqli = self._compile(_SQLI_PATTERNS + (extra_sqli or []))
        self._xss = self._compile(_XSS_PATTERNS + (extra_xss or []))
        self._cmdi = self._compile(_CMDI_PATTERNS + (extra_cmdi or []))
        self._keywords = self._compile(_MALICIOUS_KEYWORDS + (extra_keywords or []))
        self._ua = self._compile(_SUSPICIOUS_UA_PATTERNS + (extra_ua or []))

        # Port scan state: src_ip -> _PortScanState
        self._scan_state: Dict[str, _PortScanState] = defaultdict(_PortScanState)

        logger.info(
            "SignatureEngine loaded: %d SQLi, %d XSS, %d CMDi, %d keyword, %d UA patterns",
            len(self._sqli), len(self._xss), len(self._cmdi),
            len(self._keywords), len(self._ua),
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def inspect(self, pkt_meta: Dict) -> List[SignatureMatch]:
        """
        Inspect a packet metadata dict and return all matching signatures.

        pkt_meta keys:
            src_ip, dst_ip, dst_port, src_port,
            payload_str (decoded payload text or ""),
            user_agent (str or ""),
            tcp_flags (str)
        """
        results: List[SignatureMatch] = []

        payload: str = pkt_meta.get("payload_str", "")
        user_agent: str = pkt_meta.get("user_agent", "")
        src_ip: str = pkt_meta.get("src_ip", "")
        dst_port: int = pkt_meta.get("dst_port", 0)

        if payload:
            # Sanitize: limit to 8 KB to avoid ReDoS on huge payloads
            payload_safe = payload[:8192]

            m = self._match_patterns(self._sqli, payload_safe)
            if m:
                results.append(SignatureMatch(
                    matched=True, category="sql_injection",
                    confidence=self._cfg.sqli_confidence,
                    evidence=f"SQLi pattern in payload", pattern_hit=m,
                ))

            m = self._match_patterns(self._xss, payload_safe)
            if m:
                results.append(SignatureMatch(
                    matched=True, category="xss",
                    confidence=self._cfg.xss_confidence,
                    evidence="XSS pattern in payload", pattern_hit=m,
                ))

            m = self._match_patterns(self._cmdi, payload_safe)
            if m:
                results.append(SignatureMatch(
                    matched=True, category="command_injection",
                    confidence=self._cfg.cmdi_confidence,
                    evidence="Command injection pattern in payload", pattern_hit=m,
                ))

            m = self._match_patterns(self._keywords, payload_safe)
            if m:
                results.append(SignatureMatch(
                    matched=True, category="malicious_keyword",
                    confidence=self._cfg.keyword_confidence,
                    evidence="Malicious tool/keyword in payload", pattern_hit=m,
                ))

        if user_agent:
            m = self._match_patterns(self._ua, user_agent)
            if m:
                results.append(SignatureMatch(
                    matched=True, category="suspicious_user_agent",
                    confidence=self._cfg.ua_confidence,
                    evidence=f"Suspicious UA: {user_agent[:80]}", pattern_hit=m,
                ))

        # Port scan detection
        scan = self._check_port_scan(src_ip, dst_port)
        if scan:
            results.append(scan)

        return results

    def flush_stale_scan_state(self, max_idle_seconds: float = 120.0) -> None:
        """Evict idle source IPs from port scan tracker."""
        now = time.time()
        stale = [
            ip for ip, s in self._scan_state.items()
            if not s.ports_contacted or
               (now - s.ports_contacted[-1][0]) > max_idle_seconds
        ]
        for ip in stale:
            del self._scan_state[ip]

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compile(patterns: List[str]) -> List[Pattern]:
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as exc:
                logger.warning("Failed to compile pattern %r: %s", p, exc)
        return compiled

    @staticmethod
    def _match_patterns(patterns: List[Pattern], text: str) -> str:
        """Return the first matched pattern string, or empty string."""
        for pat in patterns:
            try:
                m = pat.search(text)
                if m:
                    return m.group(0)[:120]   # cap evidence length
            except Exception:
                pass
        return ""

    def _check_port_scan(self, src_ip: str, dst_port: int) -> Optional[SignatureMatch]:
        if not src_ip or dst_port == 0:
            return None

        now = time.time()
        state = self._scan_state[src_ip]
        cutoff = now - self._cfg.port_scan_window_seconds

        # Evict old entries
        while state.ports_contacted and state.ports_contacted[0][0] < cutoff:
            state.ports_contacted.popleft()

        state.ports_contacted.append((now, dst_port))

        unique_ports = len({p for _, p in state.ports_contacted})
        if unique_ports >= self._cfg.port_scan_unique_ports_threshold:
            confidence = min(
                self._cfg.port_scan_min_confidence + (unique_ports - self._cfg.port_scan_unique_ports_threshold) * 0.01,
                0.98,
            )
            return SignatureMatch(
                matched=True,
                category="port_scan",
                confidence=confidence,
                evidence=(
                    f"{unique_ports} unique ports in "
                    f"{self._cfg.port_scan_window_seconds:.0f}s window"
                ),
            )
        return None
