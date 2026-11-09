"""
penetration_testing.intelligence.knowledge_base
================================================

A lightweight, dependency-free knowledge base — an ARTEX port of
CyberStrikeAI's ``knowledge_base/`` concept.

Entries are curated JSON documents under ``penetration_testing/knowledge/``,
one per vulnerability class, each with detection hints, remediation and
references. The loader indexes them by category and keyword and offers:

* ``for_category(value)`` — exact lookup by VulnCategory value.
* ``search(query)`` — keyword-scored retrieval (no external vector DB needed).
* ``enrich(finding)`` — fills a finding's remediation/references from the KB
  when the analysis layer left them empty, keeping curated guidance consistent.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_KB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "knowledge")


@dataclass
class KnowledgeEntry:
    id: str
    category: str
    title: str
    summary: str = ""
    detection: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "category": self.category, "title": self.title,
            "summary": self.summary, "detection": self.detection,
            "remediation": self.remediation, "references": self.references,
            "keywords": self.keywords,
        }


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9][a-z0-9\-]+", (text or "").lower())


class KnowledgeBase:
    def __init__(self, directory: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        self.directory = directory or _KB_DIR
        self.logger = logger or logging.getLogger(__name__)
        self._entries: List[KnowledgeEntry] = []
        self._by_category: Dict[str, KnowledgeEntry] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.isdir(self.directory):
            self.logger.warning("Knowledge directory missing: %s", self.directory)
            return
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.directory, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                entry = KnowledgeEntry(
                    id=raw["id"], category=raw["category"], title=raw["title"],
                    summary=raw.get("summary", ""), detection=raw.get("detection", ""),
                    remediation=raw.get("remediation", ""),
                    references=list(raw.get("references", [])),
                    keywords=[k.lower() for k in raw.get("keywords", [])],
                )
            except (OSError, KeyError, json.JSONDecodeError) as exc:
                self.logger.warning("Skipping KB file %s: %s", name, exc)
                continue
            self._entries.append(entry)
            self._by_category.setdefault(entry.category, entry)

    # ── queries ──────────────────────────────────────────────────────────────
    def __len__(self) -> int:
        return len(self._entries)

    def all(self) -> List[KnowledgeEntry]:
        return list(self._entries)

    def for_category(self, category_value: str) -> Optional[KnowledgeEntry]:
        return self._by_category.get(category_value)

    def search(self, query: str, limit: int = 5) -> List[KnowledgeEntry]:
        terms = set(_tokenize(query))
        if not terms:
            return []
        scored: List[tuple] = []
        for e in self._entries:
            hay = set(e.keywords) | set(_tokenize(e.title)) | set(_tokenize(e.summary)) \
                | {e.category}
            score = len(terms & hay)
            # keyword matches weigh double
            score += len(terms & set(e.keywords))
            if score:
                scored.append((score, e))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:limit]]

    def enrich(self, finding: Any) -> Any:
        """Fill a Finding's remediation/references from the KB when empty.

        Accepts any object exposing ``category`` (with a ``.value``),
        ``remediation`` and ``references`` attributes. Never overwrites
        operator/analysis-provided values.
        """
        cat_value = getattr(getattr(finding, "category", None), "value",
                            getattr(finding, "category", None))
        entry = self.for_category(str(cat_value))
        if entry is None:
            return finding
        if not getattr(finding, "remediation", ""):
            finding.remediation = entry.remediation
        refs = getattr(finding, "references", None)
        if isinstance(refs, list) and not refs:
            finding.references = list(entry.references)
        return finding
