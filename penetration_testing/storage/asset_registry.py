"""
penetration_testing.storage.asset_registry
===========================================

Asset management — an ARTEX port of CyberStrikeAI's asset-management concept.

Normalizes and de-duplicates the hosts, IP addresses, ports and services
discovered across engagements, tracking which session first saw each asset and
how many times it has been observed. This turns scattered per-task output into a
single, queryable inventory.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


ASSET_KINDS = ("host", "ip", "port", "service")


def _norm_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


@dataclass
class Asset:
    kind: str                           # host | ip | port | service
    value: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    observations: int = 1
    first_session: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "value": self.value, "metadata": self.metadata,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "observations": self.observations, "first_session": self.first_session,
        }


class AssetRegistry:
    def __init__(self):
        self._assets: Dict[str, Asset] = {}
        self._lock = threading.Lock()

    # ── ingestion ────────────────────────────────────────────────────────────
    def add(self, kind: str, value: str, *, session_id: str = "",
            metadata: Optional[Dict[str, Any]] = None) -> Optional[Asset]:
        if kind not in ASSET_KINDS:
            return None
        value = self._normalize(kind, value)
        if not value:
            return None
        with self._lock:
            existing = self._assets.get(f"{kind}:{value}")
            if existing:
                existing.observations += 1
                existing.last_seen = time.time()
                if metadata:
                    existing.metadata.update(metadata)
                return existing
            asset = Asset(kind=kind, value=value, metadata=metadata or {},
                          first_session=session_id)
            self._assets[asset.key] = asset
            return asset

    @staticmethod
    def _normalize(kind: str, value: Any) -> str:
        if kind == "host":
            return _norm_host(str(value))
        if kind == "ip":
            try:
                return str(ipaddress.ip_address(str(value).strip()))
            except ValueError:
                return ""
        if kind == "port":
            try:
                p = int(value)
                return str(p) if 0 < p <= 65535 else ""
            except (TypeError, ValueError):
                return ""
        if kind == "service":
            return str(value).strip().lower()
        return ""

    def ingest_session(self, session: Any) -> Dict[str, int]:
        """Extract assets from an EngagementSession's task results."""
        sid = getattr(session, "session_id", "")
        added = 0
        for task in getattr(session, "tasks", []):
            result = getattr(task, "result", {}) or {}
            added += self._ingest_result(result, sid)
        return {"assets_total": len(self._assets), "ingested_from_session": added}

    def _ingest_result(self, result: Dict[str, Any], sid: str) -> int:
        count = 0
        for sub in result.get("subdomains", []) or []:
            host = sub.get("subdomain") if isinstance(sub, dict) else sub
            if self.add("host", host, session_id=sid):
                count += 1
            ip = sub.get("ip") if isinstance(sub, dict) else None
            if ip and self.add("ip", ip, session_id=sid):
                count += 1
        for host in result.get("port_scan", []) or []:
            hostname = host.get("target") if isinstance(host, dict) else None
            if hostname:
                self.add("host", hostname, session_id=sid)
            for port in (host.get("ports", []) if isinstance(host, dict) else []):
                if self.add("port", port.get("port"), session_id=sid,
                            metadata={"service": port.get("service")}):
                    count += 1
                if port.get("service"):
                    self.add("service", port.get("service"), session_id=sid)
        return count

    # ── queries ──────────────────────────────────────────────────────────────
    def all(self) -> List[Asset]:
        return list(self._assets.values())

    def by_kind(self, kind: str) -> List[Asset]:
        return [a for a in self._assets.values() if a.kind == kind]

    def stats(self) -> Dict[str, int]:
        out = {k: 0 for k in ASSET_KINDS}
        for a in self._assets.values():
            out[a.kind] += 1
        out["total"] = len(self._assets)
        return out
