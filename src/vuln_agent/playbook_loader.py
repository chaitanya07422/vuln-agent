from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class PlaybookStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        self._cache.clear()
        if not self.root.is_dir():
            return
        for path in sorted(self.root.glob("*.yaml")):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text()) or {}
            self._cache[path.stem] = data

    def for_tech(self, tags: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        wanted = set(tags or [])
        merged: Dict[str, List[Dict[str, Any]]] = {}
        for name, book in self._cache.items():
            book_tags = set(book.get("tech_tags") or [])
            is_generic = "generic" in book_tags or name == "generic"
            if not is_generic and not (book_tags & wanted):
                continue
            for section, steps in book.items():
                if section == "tech_tags" or not isinstance(steps, list):
                    continue
                merged.setdefault(section, []).extend(steps)
        return merged

    def section(self, tags: List[str], name: str) -> List[Dict[str, Any]]:
        return list(self.for_tech(tags).get(name) or [])


def default_playbook_store(config_hint: Optional[str] = None) -> PlaybookStore:
    candidates = [
        Path("playbooks"),
        Path.cwd() / "playbooks",
    ]
    if config_hint:
        candidates.insert(0, Path(config_hint).resolve().parent.parent / "playbooks")
    for c in candidates:
        if c.is_dir():
            return PlaybookStore(c.resolve())
    return PlaybookStore(Path("playbooks"))
