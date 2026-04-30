"""Shared helpers for reading structured plugin input."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple


def resolve_entity_values(
    payload: Dict,
    entity: str,
    value_attribute: str = "value",
    host_attribute: str = "host",
) -> Tuple[str, List[str]]:
    """Return the most recent host plus unique values for a given entity.

    Plugins use this to share the same fact-selection behavior without each
    script reimplementing the payload traversal.
    """

    host = payload.get("target", "")
    values: List[str] = []

    for fact in payload.get("facts", []):
        if fact.get("entity") != entity:
            continue

        attrs = fact.get("attrs", {})
        host = attrs.get(host_attribute, host)
        value = attrs.get(value_attribute)
        if isinstance(value, str) and value and value not in values:
            values.append(value)

    return host or payload.get("target", ""), values


def resolve_web_host(
    payload: Dict,
    entity_order: Iterable[str] = ("web_service", "site_profile"),
    host_attribute: str = "host",
) -> str:
    """Resolve the best host value for web-oriented plugins."""

    host = payload.get("target", "")
    preferred = tuple(entity_order)

    for fact in payload.get("facts", []):
        entity = fact.get("entity")
        if entity not in preferred:
            continue

        attrs = fact.get("attrs", {})
        host = attrs.get(host_attribute, host)
        if entity == preferred[0] and host:
            break

    return host or payload.get("target", "")


def resolve_web_host_and_provider(
    payload: Dict,
    host_entity_order: Iterable[str] = ("web_service", "site_profile"),
    host_attribute: str = "host",
    provider_attribute: str = "provider",
) -> Tuple[str, Optional[str]]:
    """Resolve a web host plus the first discovered provider hint."""

    host = payload.get("target", "")
    provider: Optional[str] = None
    preferred = tuple(host_entity_order)

    for fact in payload.get("facts", []):
        entity = fact.get("entity")
        attrs = fact.get("attrs", {})

        if entity in preferred:
            host = attrs.get(host_attribute, host)
            if entity == "site_profile":
                provider = attrs.get(provider_attribute) or provider
            if entity == preferred[0] and host:
                break

    return host or payload.get("target", ""), provider
