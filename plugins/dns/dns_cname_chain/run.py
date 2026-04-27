#!/usr/bin/env python3
"""CNAME chain resolver.

Follows CNAME records up to a maximum depth and verifies the terminal target
provides an address record. Emits a `TestOutput` JSON document.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    import dns.exception
    import dns.resolver
except ImportError as exc:  # pragma: no cover - dependency hint for operators
    raise SystemExit(
        json.dumps(
            {
                "test_id": "dns_cname_chain",
                "target": "",
                "status": "error",
                "severity": "informational",
                "evidence": {},
                "recommendations": ["Install dnspython >= 2.4 in the environment"],
                "notes": f"Missing dependency: {exc}",
            }
        )
    )

MAX_DEPTH = 3
TEST_ID = "dns_cname_chain"


@dataclass
class ChainStep:
    source: str
    target: str


class DepthExceeded(Exception):
    """CNAME chain exceeded the maximum allowed depth."""

    def __init__(self, chain: List[ChainStep], terminal: str, depth: int) -> None:
        super().__init__(f"depth exceeded at {terminal}")
        self.chain = list(chain)
        self.terminal = terminal
        self.depth = depth


class LoopDetected(Exception):
    """Detected a loop while traversing the CNAME chain."""

    def __init__(self, chain: List[ChainStep], loop_point: str) -> None:
        super().__init__(f"loop detected at {loop_point}")
        self.chain = list(chain)
        self.loop_point = loop_point


class ResolutionError(Exception):
    """Generic resolution failure."""

    def __init__(self, message: str, chain: Optional[List[ChainStep]] = None, terminal: Optional[str] = None) -> None:
        super().__init__(message)
        self.chain = list(chain) if chain is not None else []
        self.terminal = terminal


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def find_cname_fact(payload: Dict) -> Optional[Dict]:
    for fact in payload.get("facts", []):
        if fact.get("entity") != "dns_record":
            continue
        attrs = fact.get("attrs", {})
        if attrs.get("type", "").lower() == "cname":
            return attrs
    return None


def normalize_name(name: str) -> str:
    return name.rstrip(".")


def follow_chain(resolver: dns.resolver.Resolver, start: str) -> tuple[List[ChainStep], str, int]:
    chain: List[ChainStep] = []
    visited = set()
    current = normalize_name(start)
    depth = 0

    while depth < MAX_DEPTH:
        if current in visited:
            raise LoopDetected(chain, current)
        visited.add(current)
        try:
            answers = resolver.resolve(current, "CNAME")
        except dns.resolver.NXDOMAIN as exc:  # pragma: no cover - network dependent
            raise ResolutionError(f"{current} returned NXDOMAIN: {exc}", chain, current) from exc
        except dns.resolver.NoAnswer:
            return chain, current, depth
        except dns.exception.DNSException as exc:  # pragma: no cover - network dependent
            raise ResolutionError(str(exc), chain, current) from exc

        if not answers:
            return chain, current, depth

        target = normalize_name(str(answers[0].target))
        chain.append(ChainStep(source=current, target=target))
        current = target
        depth += 1

    # We exhausted our budget; see if another hop still exists.
    try:
        extra_answers = resolver.resolve(current, "CNAME")
    except dns.resolver.NoAnswer:
        return chain, current, depth
    except dns.resolver.NXDOMAIN as exc:  # pragma: no cover - network dependent
        raise ResolutionError(f"{current} returned NXDOMAIN: {exc}", chain, current) from exc
    except dns.exception.DNSException as exc:  # pragma: no cover - network dependent
        raise ResolutionError(str(exc), chain, current) from exc

    if extra_answers:
        raise DepthExceeded(chain, current, depth)

    return chain, current, depth


def resolve_terminal_addresses(resolver: dns.resolver.Resolver, host: str) -> List[str]:
    answers = []
    errors = []
    for record_type in ("A", "AAAA"):
        try:
            response = resolver.resolve(host, record_type)
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:  # pragma: no cover - network dependent
            errors.append(str(exc))
            continue
        answers.extend(str(item) for item in response)
    if answers:
        return answers
    if errors:
        raise ResolutionError("; ".join(errors))
    raise ResolutionError(f"{host} has no address records")


def serialize_chain(chain: List[ChainStep]) -> List[Dict[str, str]]:
    return [{"from": step.source, "to": step.target} for step in chain]


def main() -> None:
    payload = load_input()
    attrs = find_cname_fact(payload)
    target_host = normalize_name(attrs.get("name", "") if attrs else payload.get("target", ""))

    if not attrs or not target_host:
        output = {
            "test_id": TEST_ID,
            "target": target_host,
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery provides CNAME facts with name/value attributes"],
            "notes": "No CNAME fact supplied to plugin",
        }
        json.dump(output, sys.stdout)
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 5.0

    try:
        chain, terminal, depth = follow_chain(resolver, target_host)
        addresses = resolve_terminal_addresses(resolver, terminal)
    except DepthExceeded as exc:
        output = {
            "test_id": TEST_ID,
            "target": target_host,
            "status": "warn",
            "severity": "medium",
            "evidence": {
                "max_depth": MAX_DEPTH,
                "observed_depth": exc.depth,
                "chain": serialize_chain(exc.chain),
                "terminal": exc.terminal,
            },
            "recommendations": ["Flatten the CNAME chain or point directly to the terminal host"],
            "notes": f"CNAME chain exceeded maximum depth of {MAX_DEPTH}",
        }
    except LoopDetected as exc:
        output = {
            "test_id": TEST_ID,
            "target": target_host,
            "status": "fail",
            "severity": "high",
            "evidence": {
                "chain": serialize_chain(exc.chain),
                "loop_point": exc.loop_point,
            },
            "recommendations": ["Break the CNAME loop by updating DNS records"],
            "notes": "Detected a loop while following the CNAME chain",
        }
    except ResolutionError as exc:
        chain_evidence = exc.chain if exc.chain else (locals().get("chain") or [])
        terminal_ref = exc.terminal or locals().get("terminal", target_host)
        output = {
            "test_id": TEST_ID,
            "target": target_host,
            "status": "error",
            "severity": "informational",
            "evidence": {
                "chain": serialize_chain(chain_evidence),
                "terminal": terminal_ref,
            },
            "recommendations": ["Verify the CNAME target exists and resolves to an address"],
            "notes": str(exc),
        }
    else:
        output = {
            "test_id": TEST_ID,
            "target": target_host,
            "status": "pass",
            "severity": "informational",
            "evidence": {
                "chain": serialize_chain(chain),
                "terminal": terminal,
                "addresses": addresses,
                "depth": depth,
            },
            "recommendations": [],
            "notes": None,
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
