"""Engagement Memory provider — temporal graph state for assessments.

This provider gives Hermes a local-first temporal engagement graph that can be
used as the core state tracker during authorized security work.  It records
observations, target state changes, findings, failed/successful validation
attempts, and entity relationships over time.  Optional Graphiti/Zep or Mem0
mirroring can be enabled by config/env, but local storage is always available.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from agent.memory_provider import MemoryProvider
from tools.registry import tool_error

logger = logging.getLogger(__name__)

_MAX_TEXT = 2000
_DEFAULT_LIMIT = 20


RECORD_SCHEMA = {
    "name": "engagement_record",
    "description": (
        "Record a temporal engagement-memory observation: target state, finding, "
        "validation attempt, credential exposure evidence, tool result summary, or relationship."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "event_type": {"type": "string", "description": "Observation type, e.g. port_state, finding, exploit_attempt, credential_evidence."},
            "summary": {"type": "string", "description": "Concise operator-facing event summary."},
            "entities": {"type": "array", "items": {"type": "object"}, "description": "Entities involved: {id,type,name,state,attributes}."},
            "relations": {"type": "array", "items": {"type": "object"}, "description": "Relations: {source,relation,target,valid_from,valid_to,attributes}."},
            "valid_from": {"type": "string", "description": "Optional ISO timestamp when this state became true."},
            "valid_to": {"type": "string", "description": "Optional ISO timestamp when this state stopped being true."},
            "confidence": {"type": "number", "description": "0.0-1.0 confidence."},
            "tags": {"type": "array", "items": {"type": "string"}},
            "metadata": {"type": "object", "description": "Non-secret evidence metadata such as command, file, line, status."},
        },
        "required": ["event_type", "summary"],
    },
}

TIMELINE_SCHEMA = {
    "name": "engagement_timeline",
    "description": "Retrieve chronological engagement-memory events, optionally filtered by query, entity, or tag.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Case-insensitive text filter."},
            "entity": {"type": "string", "description": "Entity id/name filter."},
            "tag": {"type": "string", "description": "Tag filter."},
            "limit": {"type": "integer", "description": "Max events to return (default 20, max 100)."},
        },
        "required": [],
    },
}

STATE_SCHEMA = {
    "name": "engagement_state",
    "description": "Summarize current engagement graph state for targets, findings, relationships, and recent timeline changes.",
    "parameters": {
        "type": "object",
        "properties": {
            "entity": {"type": "string", "description": "Optional entity id/name to focus the state summary."},
            "include_history": {"type": "boolean", "description": "Include recent events alongside current state."},
        },
        "required": [],
    },
}


@dataclass
class EngagementStore:
    path: Path
    _lock: threading.RLock = field(default_factory=threading.RLock)
    data: dict[str, Any] = field(default_factory=dict)

    def load(self) -> None:
        with self._lock:
            if self.path.exists():
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            if not self.data:
                self.data = {"version": 1, "events": [], "entities": {}, "relations": []}

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.data.setdefault("events", []).append(event)
            for entity in event.get("entities", []):
                if not isinstance(entity, dict):
                    continue
                entity_id = str(entity.get("id") or entity.get("name") or "").strip()
                if not entity_id:
                    continue
                current = self.data.setdefault("entities", {}).get(entity_id, {})
                merged = {**current, **entity, "id": entity_id, "updated_at": event["observed_at"]}
                self.data["entities"][entity_id] = merged
            for relation in event.get("relations", []):
                if isinstance(relation, dict):
                    rel = dict(relation)
                    rel.setdefault("observed_at", event["observed_at"])
                    rel.setdefault("event_id", event["id"])
                    self.data.setdefault("relations", []).append(rel)
            self.save()
        return event

    def query_events(self, query: str = "", entity: str = "", tag: str = "", limit: int = _DEFAULT_LIMIT) -> list[dict[str, Any]]:
        query_l = query.lower().strip()
        entity_l = entity.lower().strip()
        tag_l = tag.lower().strip()
        limit = max(1, min(int(limit or _DEFAULT_LIMIT), 100))
        results: list[dict[str, Any]] = []
        with self._lock:
            events = list(self.data.get("events", []))
        for event in reversed(events):
            haystack = json.dumps(event, ensure_ascii=False).lower()
            if query_l and query_l not in haystack:
                continue
            if entity_l and entity_l not in haystack:
                continue
            if tag_l and tag_l not in [str(t).lower() for t in event.get("tags", [])]:
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return list(reversed(results))

    def state(self, entity: str = "", include_history: bool = False) -> dict[str, Any]:
        entity_l = entity.lower().strip()
        with self._lock:
            entities = dict(self.data.get("entities", {}))
            relations = list(self.data.get("relations", []))
            events = list(self.data.get("events", []))
        if entity_l:
            entities = {k: v for k, v in entities.items() if entity_l in k.lower() or entity_l in json.dumps(v, ensure_ascii=False).lower()}
            relations = [r for r in relations if entity_l in json.dumps(r, ensure_ascii=False).lower()]
            events = [e for e in events if entity_l in json.dumps(e, ensure_ascii=False).lower()]
        current_relations = [r for r in relations if not r.get("valid_to")]
        payload = {
            "entity_count": len(entities),
            "relation_count": len(current_relations),
            "entities": entities,
            "relations": current_relations[-100:],
        }
        if include_history:
            payload["recent_events"] = events[-20:]
        return payload


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clean_text(value: Any, limit: int = _MAX_TEXT) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text.replace("\x00", "")[:limit]


def _coerce_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "off", "disabled"}:
            return False
    return bool(value)


def _load_config(hermes_home: str | Path | None = None) -> dict[str, Any]:
    home = Path(hermes_home) if hermes_home else None
    config = {
        "backend": os.environ.get("ENGAGEMENT_MEMORY_BACKEND", "local"),
        "graphiti_url": os.environ.get("GRAPHITI_URL") or os.environ.get("ZEP_GRAPHITI_URL", ""),
        "zep_api_key": os.environ.get("ZEP_API_KEY", ""),
        "mem0_api_key": os.environ.get("MEM0_API_KEY", ""),
        "auto_record_turns": True,
    }
    if home:
        cfg_path = home / "engagement_memory.json"
        if cfg_path.exists():
            file_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            config.update({k: v for k, v in file_cfg.items() if v not in (None, "")})
    return config


class EngagementMemoryProvider(MemoryProvider):
    """Local-first temporal graph provider for engagement state."""

    core_provider = True

    def __init__(self) -> None:
        self._session_id = ""
        self._platform = "cli"
        self._hermes_home = None
        self._store: EngagementStore | None = None
        self._config: dict[str, Any] = {}
        self._prefetch_result = ""
        self._prefetch_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "engagement"

    def is_available(self) -> bool:
        return True

    def save_config(self, values, hermes_home):
        config_path = Path(hermes_home) / "engagement_memory.json"
        existing = {}
        if config_path.exists():
            existing = json.loads(config_path.read_text(encoding="utf-8"))
        existing.update(values)
        config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    def get_config_schema(self):
        return [
            {"key": "backend", "description": "Mirror backend: local, kuzu/mem0g, graphiti, or mem0", "default": "local", "choices": ["local", "kuzu", "mem0g", "graphiti", "mem0"]},
            {"key": "graphiti_url", "description": "Optional Graphiti/Zep endpoint URL", "default": "", "env_var": "GRAPHITI_URL"},
            {"key": "zep_api_key", "description": "Optional Zep API key for Graphiti mirroring", "secret": True, "required": False, "env_var": "ZEP_API_KEY"},
            {"key": "auto_record_turns", "description": "Record completed user/assistant turns as timeline events", "default": "true", "choices": ["true", "false"]},
        ]

    def initialize(self, session_id: str, **kwargs) -> None:
        self._session_id = session_id or "default"
        self._platform = kwargs.get("platform") or "cli"
        self._hermes_home = Path(kwargs.get("hermes_home") or Path.home() / ".hermes")
        self._config = _load_config(self._hermes_home)
        runtime_cfg = kwargs.get("engagement_config") or {}
        if isinstance(runtime_cfg, dict):
            self._config.update({k: v for k, v in runtime_cfg.items() if v not in (None, "")})
        self._config["auto_record_turns"] = _coerce_bool(self._config.get("auto_record_turns"), True)
        safe_session = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in self._session_id)[:120] or "default"
        self._store = EngagementStore(self._hermes_home / "engagement-memory" / f"{safe_session}.json")
        self._store.load()

    def system_prompt_block(self) -> str:
        backend = self._config.get("backend", "local")
        return (
            "# Engagement Memory\n"
            "Temporal engagement memory is active. Use engagement_record for important target state changes, "
            "failed/successful validation attempts, findings, credentials evidence metadata, and relationships. "
            "Use engagement_state before planning follow-up actions so you account for changed target state. "
            f"Backend: {backend} (local-first)."
        )

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        with self._prefetch_lock:
            result = self._prefetch_result
            self._prefetch_result = ""
        if result:
            return result
        if not self._store or not query:
            return ""
        events = self._store.query_events(query=query, limit=5)
        if not events:
            return ""
        lines = [f"- {e.get('observed_at')}: {e.get('event_type')} — {e.get('summary')}" for e in events]
        return "## Engagement Memory\n" + "\n".join(lines)

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        if not self._store or not query:
            return
        events = self._store.query_events(query=query, limit=5)
        if not events:
            return
        lines = [f"- {e.get('observed_at')}: {e.get('event_type')} — {e.get('summary')}" for e in events]
        with self._prefetch_lock:
            self._prefetch_result = "## Engagement Memory\n" + "\n".join(lines)

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "") -> None:
        if not self._config.get("auto_record_turns", True) or not self._store:
            return
        summary = _clean_text({"user": user_content, "assistant": assistant_content}, limit=1200)
        self._append_event({
            "event_type": "conversation_turn",
            "summary": summary,
            "entities": [],
            "relations": [],
            "confidence": 1.0,
            "tags": ["conversation", self._platform],
            "metadata": {"session_id": session_id or self._session_id},
        })

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [RECORD_SCHEMA, TIMELINE_SCHEMA, STATE_SCHEMA]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any], **kwargs) -> str:
        if not self._store:
            return tool_error("Engagement memory is not initialized")
        if tool_name == "engagement_record":
            event = self._append_event({
                "event_type": args.get("event_type", "observation"),
                "summary": _clean_text(args.get("summary", "")),
                "entities": args.get("entities") or [],
                "relations": args.get("relations") or [],
                "valid_from": args.get("valid_from") or _now_iso(),
                "valid_to": args.get("valid_to") or "",
                "confidence": args.get("confidence", 1.0),
                "tags": args.get("tags") or [],
                "metadata": args.get("metadata") or {},
            })
            return json.dumps({"success": True, "event": event}, ensure_ascii=False)
        if tool_name == "engagement_timeline":
            events = self._store.query_events(
                query=args.get("query", ""),
                entity=args.get("entity", ""),
                tag=args.get("tag", ""),
                limit=args.get("limit", _DEFAULT_LIMIT),
            )
            return json.dumps({"success": True, "events": events, "count": len(events)}, ensure_ascii=False)
        if tool_name == "engagement_state":
            state = self._store.state(entity=args.get("entity", ""), include_history=bool(args.get("include_history", False)))
            return json.dumps({"success": True, "state": state}, ensure_ascii=False)
        return tool_error(f"Unknown engagement memory tool: {tool_name}")

    def on_memory_write(self, action, target, content, metadata=None):
        if not self._store:
            return
        self._append_event({
            "event_type": "memory_write",
            "summary": _clean_text({"action": action, "target": target, "content": content}, limit=1000),
            "entities": [],
            "relations": [],
            "confidence": 1.0,
            "tags": ["memory_write"],
            "metadata": metadata or {},
        })

    def _append_event(self, fields: dict[str, Any]) -> dict[str, Any]:
        if not self._store:
            raise RuntimeError("Engagement memory store is not initialized")
        event = {
            "id": fields.get("id") or str(uuid.uuid4()),
            "observed_at": fields.get("observed_at") or _now_iso(),
            "session_id": self._session_id,
            "event_type": str(fields.get("event_type") or "observation"),
            "summary": _clean_text(fields.get("summary", "")),
            "entities": fields.get("entities") or [],
            "relations": fields.get("relations") or [],
            "valid_from": fields.get("valid_from") or _now_iso(),
            "valid_to": fields.get("valid_to") or "",
            "confidence": fields.get("confidence", 1.0),
            "tags": fields.get("tags") or [],
            "metadata": fields.get("metadata") or {},
        }
        stored = self._store.append_event(event)
        self._mirror_event_best_effort(stored)
        return stored

    def _mirror_event_best_effort(self, event: dict[str, Any]) -> None:
        backend = str(self._config.get("backend", "local")).lower()
        if backend == "local":
            return
        if backend in {"kuzu", "mem0g"} and self._mirror_to_kuzu(event):
            return
        try:
            mirror_path = (self._hermes_home or Path.home() / ".hermes") / "engagement-memory" / "mirror-queue.jsonl"
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            mirror_path.open("a", encoding="utf-8").write(json.dumps({"backend": backend, "event": event}, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.debug("engagement memory mirror queue failed: %s", exc)

    def _mirror_to_kuzu(self, event: dict[str, Any]) -> bool:
        if importlib.util.find_spec("kuzu") is None:
            return False
        kuzu = importlib.import_module("kuzu")
        try:
            db_path = (self._hermes_home or Path.home() / ".hermes") / "engagement-memory" / "kuzu"
            db_path.mkdir(parents=True, exist_ok=True)
            db = kuzu.Database(str(db_path))
            conn = kuzu.Connection(db)
            conn.execute("CREATE NODE TABLE IF NOT EXISTS Event(id STRING, observed_at STRING, event_type STRING, summary STRING, PRIMARY KEY(id))")
            conn.execute("CREATE NODE TABLE IF NOT EXISTS Entity(id STRING, type STRING, name STRING, state STRING, updated_at STRING, PRIMARY KEY(id))")
            conn.execute("CREATE REL TABLE IF NOT EXISTS RELATED(FROM Entity TO Entity, relation STRING, observed_at STRING, event_id STRING)")
            conn.execute("CREATE (:Event {id: $id, observed_at: $observed_at, event_type: $event_type, summary: $summary})", {
                "id": event.get("id", ""),
                "observed_at": event.get("observed_at", ""),
                "event_type": event.get("event_type", ""),
                "summary": event.get("summary", ""),
            })
            for entity in event.get("entities", []):
                if not isinstance(entity, dict):
                    continue
                entity_id = str(entity.get("id") or entity.get("name") or "").strip()
                if not entity_id:
                    continue
                conn.execute("CREATE (:Entity {id: $id, type: $type, name: $name, state: $state, updated_at: $updated_at})", {
                    "id": entity_id,
                    "type": str(entity.get("type", "")),
                    "name": str(entity.get("name", entity_id)),
                    "state": str(entity.get("state", "")),
                    "updated_at": event.get("observed_at", ""),
                })
            return True
        except Exception as exc:
            logger.debug("engagement memory Kuzu mirror failed: %s", exc)
            return False


def register_memory_provider():
    return EngagementMemoryProvider()
