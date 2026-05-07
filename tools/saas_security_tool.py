#!/usr/bin/env python3
"""SaaS authorization-assessment helpers.

This module intentionally focuses on bounded, authorized BOLA/IDOR assessment
workflows: traffic capture planning, API schema extraction, identity-context
request rewriting, and replay-result analysis.  It does not deploy payloads,
modify webhook destinations, register OAuth applications, or provide C2.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from tools.registry import registry

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_OBJECT_ID_RE = re.compile(r"\b[0-9a-fA-F]{24}\b")
_NUMERIC_ID_RE = re.compile(r"(?<![\w.-])\d{4,}(?![\w.-])")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
_ID_KEY_HINTS = ("id", "uuid", "guid", "org", "organization", "tenant", "workspace", "account", "project")


def _tool_response(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _json_loads_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if stripped[0] not in "[{":
        return value
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return value


def _redact_headers(headers: dict[str, Any]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in (headers or {}).items():
        key_s = str(key)
        if key_s.lower() in _SENSITIVE_HEADER_NAMES:
            redacted[key_s] = "<redacted>"
        else:
            redacted[key_s] = str(value)
    return redacted


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    padded = payload + "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _extract_ids_from_text(text: str) -> dict[str, list[str]]:
    if not text:
        return {"uuids": [], "object_ids": [], "numeric_ids": [], "jwts": []}
    return {
        "uuids": sorted(set(_UUID_RE.findall(text))),
        "object_ids": sorted(set(_OBJECT_ID_RE.findall(text))),
        "numeric_ids": sorted(set(_NUMERIC_ID_RE.findall(text))),
        "jwts": sorted(set(_JWT_RE.findall(text))),
    }


def _walk_json_ids(value: Any, prefix: str = "") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            key_l = str(key).lower()
            if any(hint in key_l for hint in _ID_KEY_HINTS) and isinstance(item, (str, int)):
                findings.append({"path": path, "key": str(key), "value": str(item)})
            findings.extend(_walk_json_ids(item, path))
    elif isinstance(value, list):
        for idx, item in enumerate(value[:200]):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            findings.extend(_walk_json_ids(item, path))
    return findings


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = ""
    status_code: int | None = None
    response_body: Any = ""

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        return parsed.path or "/"


class TrafficAnalyzer:
    """Extract object identifiers and API shapes from captured HTTP traffic."""

    def __init__(self, records: list[CapturedRequest]):
        self.records = records

    @classmethod
    def from_file(cls, path: str | Path) -> "TrafficAnalyzer":
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        return cls(_records_from_json(data))

    def analyze(self) -> dict[str, Any]:
        endpoints: list[dict[str, Any]] = []
        jwt_claims: list[dict[str, Any]] = []
        id_index: dict[str, list[dict[str, Any]]] = {}

        for idx, record in enumerate(self.records):
            req_body = _json_loads_maybe(record.body)
            resp_body = _json_loads_maybe(record.response_body)
            request_text = json.dumps(req_body, ensure_ascii=False) if isinstance(req_body, (dict, list)) else str(req_body or "")
            response_text = json.dumps(resp_body, ensure_ascii=False) if isinstance(resp_body, (dict, list)) else str(resp_body or "")
            url_text = record.url
            combined = "\n".join([url_text, request_text, response_text])
            ids = _extract_ids_from_text(combined)
            json_id_paths = _walk_json_ids(req_body) + _walk_json_ids(resp_body)
            graphql = self._graphql_summary(req_body)
            query_params = dict(parse_qsl(urlparse(record.url).query, keep_blank_values=True))

            for token in ids["jwts"]:
                claims = _decode_jwt_payload(token)
                if claims:
                    jwt_claims.append({"record": idx, "claims": self._safe_claim_subset(claims)})

            endpoint = {
                "record": idx,
                "method": record.method.upper(),
                "host": record.host,
                "path": record.path,
                "status_code": record.status_code,
                "query_keys": sorted(query_params),
                "ids": {k: v for k, v in ids.items() if k != "jwts"},
                "json_id_paths": json_id_paths[:100],
                "graphql": graphql,
                "headers": _redact_headers(record.headers),
                "replay_candidate": bool(ids["uuids"] or ids["object_ids"] or json_id_paths),
            }
            endpoints.append(endpoint)
            for category, values in endpoint["ids"].items():
                for value in values:
                    id_index.setdefault(value, []).append({"record": idx, "category": category, "path": record.path})
            for finding in json_id_paths:
                id_index.setdefault(finding["value"], []).append(
                    {"record": idx, "category": "json_path", "path": record.path, "json_path": finding["path"]}
                )

        return {
            "success": True,
            "records_analyzed": len(self.records),
            "endpoints": endpoints,
            "id_index": id_index,
            "jwt_claims": jwt_claims[:50],
            "summary": {
                "replay_candidates": sum(1 for e in endpoints if e["replay_candidate"]),
                "unique_ids": len(id_index),
                "graphql_operations": sum(1 for e in endpoints if e["graphql"]),
            },
        }

    @staticmethod
    def _graphql_summary(body: Any) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            return None
        if "query" not in body and "operationName" not in body:
            return None
        query = str(body.get("query", ""))
        op_type = "mutation" if "mutation" in query[:120].lower() else "query"
        return {
            "operation_name": body.get("operationName") or "",
            "operation_type": op_type,
            "variables_keys": sorted((body.get("variables") or {}).keys()) if isinstance(body.get("variables"), dict) else [],
        }

    @staticmethod
    def _safe_claim_subset(claims: dict[str, Any]) -> dict[str, Any]:
        allowed = {"iss", "aud", "sub", "tid", "tenant", "org", "organization", "workspace", "account", "scope", "scp", "roles", "exp", "iat"}
        return {key: claims[key] for key in sorted(claims) if key in allowed}


class IdentityManager:
    """Track named identity contexts and build swapped-request replay plans.

    This class deliberately does not perform network I/O.  It rewrites captured
    requests so the operator can review or execute them through approved tooling.
    """

    def __init__(self):
        self._contexts: dict[str, dict[str, Any]] = {}

    def add_context(self, name: str, *, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> None:
        if not name or not str(name).strip():
            raise ValueError("context name is required")
        self._contexts[str(name)] = {"headers": headers or {}, "cookies": cookies or {}}

    def swap_context(self, request: CapturedRequest, target_context: str) -> CapturedRequest:
        if target_context not in self._contexts:
            raise KeyError(f"unknown identity context: {target_context}")
        context = self._contexts[target_context]
        headers = dict(request.headers)
        for key in list(headers):
            if key.lower() in {"authorization", "cookie"}:
                headers.pop(key, None)
        headers.update(context.get("headers") or {})
        cookies = context.get("cookies") or {}
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return CapturedRequest(
            method=request.method,
            url=request.url,
            headers=headers,
            body=request.body,
            status_code=request.status_code,
            response_body=request.response_body,
        )

    def list_contexts(self) -> list[str]:
        return sorted(self._contexts)


class ContextAwareFuzzer:
    """Build and score BOLA/IDOR replay candidates from captured traffic."""

    def __init__(self, analysis: dict[str, Any]):
        self.analysis = analysis

    def build_replay_plan(self, owner_context: str = "Context_A", alternate_context: str = "Context_B") -> dict[str, Any]:
        candidates = []
        for endpoint in self.analysis.get("endpoints", []):
            if not endpoint.get("replay_candidate"):
                continue
            candidates.append(
                {
                    "record": endpoint["record"],
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "owner_context": owner_context,
                    "alternate_context": alternate_context,
                    "test": "Replay the same request with alternate-context auth while preserving object identifiers.",
                    "expected_secure_result": "401/403/404 or response body excluding owner-only object data.",
                    "potential_issue_signal": "2xx response or alternate-context response containing owner object identifiers/data.",
                }
            )
        return {"success": True, "candidate_count": len(candidates), "candidates": candidates}

    @staticmethod
    def compare_results(owner_response: dict[str, Any], alternate_response: dict[str, Any], object_ids: list[str] | None = None) -> dict[str, Any]:
        owner_status = int(owner_response.get("status_code", 0) or 0)
        alt_status = int(alternate_response.get("status_code", 0) or 0)
        alt_body = json.dumps(alternate_response.get("body", ""), ensure_ascii=False)
        matched_ids = [oid for oid in (object_ids or []) if oid and oid in alt_body]
        suspicious = 200 <= alt_status < 300 and (matched_ids or owner_status == alt_status)
        return {
            "success": True,
            "possible_bola": bool(suspicious),
            "owner_status_code": owner_status,
            "alternate_status_code": alt_status,
            "matched_object_ids_in_alternate_response": matched_ids,
            "interpretation": (
                "Alternate identity received a successful response that may expose owner-scoped data."
                if suspicious
                else "No BOLA signal from the supplied response metadata."
            ),
        }


class PlaywrightMitmproxyBridge:
    """Plan a Playwright + mitmproxy capture session for SPA/API discovery."""

    def __init__(self, listen_host: str = "127.0.0.1", listen_port: int = 8090, output_path: str = "saas-traffic.json"):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.output_path = output_path

    def environment(self) -> dict[str, Any]:
        return {
            "mitmdump": shutil.which("mitmdump"),
            "python": shutil.which("python3") or shutil.which("python"),
            "playwright_cli": shutil.which("playwright"),
            "proxy": f"http://{self.listen_host}:{self.listen_port}",
            "output_path": self.output_path,
        }

    def launch_plan(self, target_url: str) -> dict[str, Any]:
        env = self.environment()
        return {
            "success": True,
            "target_url": target_url,
            "environment": env,
            "mitmproxy_command": [
                env["mitmdump"] or "mitmdump",
                "--listen-host", self.listen_host,
                "--listen-port", str(self.listen_port),
                "--set", "flow_detail=0",
                "-w", self.output_path,
            ],
            "playwright_proxy": env["proxy"],
            "notes": [
                "Run mitmdump in a tracked background process, then launch Playwright with the listed proxy.",
                "Authenticate only test accounts covered by the Rules of Engagement.",
                "Export/convert captured flows to HAR or JSON before analyze_traffic.",
            ],
        }


def _records_from_json(data: Any) -> list[CapturedRequest]:
    if isinstance(data, dict) and "log" in data and isinstance(data["log"], dict):
        entries = data["log"].get("entries") or []
        records = []
        for entry in entries:
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            req_headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", []) if h.get("name")}
            body = (req.get("postData") or {}).get("text", "")
            records.append(
                CapturedRequest(
                    method=req.get("method", "GET"),
                    url=req.get("url", ""),
                    headers=req_headers,
                    body=body,
                    status_code=resp.get("status"),
                    response_body=(resp.get("content") or {}).get("text", ""),
                )
            )
        return records

    if isinstance(data, dict) and "records" in data:
        data = data["records"]
    if not isinstance(data, list):
        raise ValueError("traffic JSON must be a HAR, a list of records, or {'records': [...]} object")

    records = []
    for item in data:
        if not isinstance(item, dict):
            continue
        records.append(
            CapturedRequest(
                method=str(item.get("method") or item.get("request", {}).get("method") or "GET"),
                url=str(item.get("url") or item.get("request", {}).get("url") or ""),
                headers=dict(item.get("headers") or item.get("request", {}).get("headers") or {}),
                body=item.get("body", item.get("request", {}).get("body", "")),
                status_code=item.get("status_code", item.get("response", {}).get("status_code")),
                response_body=item.get("response_body", item.get("response", {}).get("body", "")),
            )
        )
    return records


def saas_bola_assess(
    action: str,
    traffic_file: str = "",
    target_url: str = "",
    owner_response: dict[str, Any] | None = None,
    alternate_response: dict[str, Any] | None = None,
    object_ids: list[str] | None = None,
    owner_context: str = "Context_A",
    alternate_context: str = "Context_B",
) -> str:
    """Tool entry point for SaaS BOLA/IDOR assessment planning."""
    try:
        if action == "check_environment":
            return _tool_response({"success": True, "environment": PlaywrightMitmproxyBridge().environment()})
        if action == "capture_plan":
            if not target_url:
                return _tool_response({"success": False, "error": "target_url is required for capture_plan"})
            return _tool_response(PlaywrightMitmproxyBridge().launch_plan(target_url))
        if action == "analyze_traffic":
            if not traffic_file:
                return _tool_response({"success": False, "error": "traffic_file is required for analyze_traffic"})
            return _tool_response(TrafficAnalyzer.from_file(traffic_file).analyze())
        if action == "build_replay_plan":
            if not traffic_file:
                return _tool_response({"success": False, "error": "traffic_file is required for build_replay_plan"})
            analysis = TrafficAnalyzer.from_file(traffic_file).analyze()
            return _tool_response(ContextAwareFuzzer(analysis).build_replay_plan(owner_context, alternate_context))
        if action == "compare_replay_results":
            if owner_response is None or alternate_response is None:
                return _tool_response({"success": False, "error": "owner_response and alternate_response are required"})
            return _tool_response(ContextAwareFuzzer.compare_results(owner_response, alternate_response, object_ids))
        return _tool_response({"success": False, "error": f"unknown action: {action}"})
    except Exception as exc:
        return _tool_response({"success": False, "error": str(exc)})


SAAS_BOLA_SCHEMA = {
    "name": "saas_bola_assess",
    "description": (
        "Authorized SaaS BOLA/IDOR assessment helper. Plans Playwright+mitmproxy capture, "
        "analyzes HAR/JSON HTTP traffic for object IDs/JWT/API shapes, builds identity-context "
        "replay plans, and compares replay response metadata. Does not modify webhooks, register "
        "OAuth apps, deploy payloads, or perform C2."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["check_environment", "capture_plan", "analyze_traffic", "build_replay_plan", "compare_replay_results"],
            },
            "traffic_file": {"type": "string", "description": "Path to HAR or JSON traffic export."},
            "target_url": {"type": "string", "description": "Target URL for capture planning."},
            "owner_response": {"type": "object", "description": "Owner-context response metadata: {status_code, body}."},
            "alternate_response": {"type": "object", "description": "Alternate-context response metadata: {status_code, body}."},
            "object_ids": {"type": "array", "items": {"type": "string"}, "description": "Object IDs expected to stay owner-scoped."},
            "owner_context": {"type": "string", "description": "Label for the owner identity context."},
            "alternate_context": {"type": "string", "description": "Label for the alternate identity context."},
        },
        "required": ["action"],
    },
}


registry.register(
    name="saas_bola_assess",
    toolset="saas_security",
    schema=SAAS_BOLA_SCHEMA,
    handler=lambda args, **kw: saas_bola_assess(
        action=args.get("action", ""),
        traffic_file=args.get("traffic_file", ""),
        target_url=args.get("target_url", ""),
        owner_response=args.get("owner_response"),
        alternate_response=args.get("alternate_response"),
        object_ids=args.get("object_ids"),
        owner_context=args.get("owner_context", "Context_A"),
        alternate_context=args.get("alternate_context", "Context_B"),
    ),
    emoji="🧩",
)
