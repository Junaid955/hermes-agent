#!/usr/bin/env python3
"""Static-analysis service helpers for authorized code review.

The service wraps local Semgrep and CodeQL installations when available, and
also provides deterministic planning/scaffolding when those binaries are not
installed.  It is intended for defensive source review: credential discovery,
API endpoint mapping, variant analysis, and data-flow feasibility checks.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hermes_constants import get_hermes_home
from tools.registry import registry

_MAX_SNIPPET_CHARS = 1200
_DEFAULT_TIMEOUT_SECONDS = 180

_ROUTE_PATTERNS = [
    re.compile(r"@(?:app|router|blueprint)\.(get|post|put|patch|delete|options|head)\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|options|head)\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\bRoute\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(?:methods\s*=\s*)?\[([^\]]+)\]", re.I),
    re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+['\"]([^'\"]+)['\"]"),
]

_LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "java": {".java"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "php": {".php"},
}

_CODEQL_TEMPLATES: dict[str, dict[str, str]] = {
    "ssrf": {
        "javascript": """/**
 * Review scaffold: find HTTP client calls that should be checked for user-controlled URLs.
 * Extend with framework-specific RemoteFlowSource nodes for the target app.
 */
import javascript

from CallExpr call
where call.getCalleeName().regexpMatch("(fetch|request|get|post|axios)")
select call, "Review outbound request sink for SSRF controls."
""",
        "python": """/** Review scaffold: outbound request sinks for SSRF control review. */
import python

from Call call
where call.getFunc().(Name).getId().regexpMatch("(get|post|put|patch|delete|request)")
select call, "Review outbound request sink for SSRF controls."
""",
    },
    "sql_injection": {
        "python": """/** Review scaffold: database execute sinks that deserve taint follow-up. */
import python

from Call call
where call.getFunc().(Attribute).getName().regexpMatch("(execute|executemany|raw)")
select call, "Review SQL execution sink for parameterization."
""",
        "javascript": """/** Review scaffold: query sinks that deserve taint follow-up. */
import javascript

from CallExpr call
where call.getCalleeName().regexpMatch("(query|execute|raw)")
select call, "Review SQL execution sink for parameterization."
""",
    },
    "path_traversal": {
        "python": """/** Review scaffold: filesystem sinks that deserve path-normalization checks. */
import python

from Call call
where call.getFunc().(Name).getId().regexpMatch("(open|remove|unlink|rmtree|copyfile)")
select call, "Review filesystem sink for path traversal controls."
""",
        "javascript": """/** Review scaffold: filesystem sinks that deserve path-normalization checks. */
import javascript

from CallExpr call
where call.getCalleeName().regexpMatch("(readFile|writeFile|unlink|rm|createReadStream|createWriteStream)")
select call, "Review filesystem sink for path traversal controls."
""",
    },
    "permission_change": {
        "javascript": """/** Review scaffold: authorization-sensitive writes for access-control review. */
import javascript

from PropertyAccess pa
where pa.getPropertyName().regexpMatch("(role|roles|permission|permissions|isAdmin|admin)")
select pa, "Review permission-changing code path for authorization checks."
""",
        "python": """/** Review scaffold: authorization-sensitive writes for access-control review. */
import python

from Attribute attr
where attr.getName().regexpMatch("(role|roles|permission|permissions|is_admin|admin)")
select attr, "Review permission-changing code path for authorization checks."
""",
    },
}


def _tool_response(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _service_root() -> Path:
    root = get_hermes_home() / "static-analysis"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _safe_name(value: str, fallback: str = "workspace") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned[:80] or fallback


def _run_command(args: list[str], timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS, cwd: str | Path | None = None) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_seconds)),
            check=False,
        )
    except FileNotFoundError:
        return {"success": False, "error": f"binary not found: {args[0]}", "command": args}
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "error": f"command timed out after {timeout_seconds}s",
            "command": args,
            "stdout": (exc.stdout or "")[-4000:],
            "stderr": (exc.stderr or "")[-4000:],
        }
    return {
        "success": completed.returncode == 0,
        "returncode": completed.returncode,
        "command": args,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": completed.stdout[-20000:],
        "stderr": completed.stderr[-8000:],
    }


def _safe_extract_zip(zip_path: Path, destination: Path) -> list[str]:
    extracted: list[str] = []
    destination.mkdir(parents=True, exist_ok=True)
    dest_root = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target = (dest_root / member.filename).resolve()
            if not str(target).startswith(str(dest_root) + "/") and target != dest_root:
                raise ValueError(f"unsafe zip member path: {member.filename}")
            archive.extract(member, dest_root)
            extracted.append(member.filename)
    return extracted[:500]


def _default_workspace_for_source(source: str) -> Path:
    parsed = urlparse(source)
    raw = Path(parsed.path).stem if parsed.scheme else Path(source).stem
    return _service_root() / "workspaces" / _safe_name(raw or "workspace")


def _read_line_snippet(path: Path, line: int, context: int = 2) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, line - context)
    end = min(len(lines), line + context)
    snippet = "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))
    return snippet[:_MAX_SNIPPET_CHARS]


def _summarize_semgrep_findings(data: dict[str, Any], target_path: Path) -> dict[str, Any]:
    findings = []
    for result in data.get("results", [])[:200]:
        path = _resolve_path(result.get("path", "")) if result.get("path") else None
        start = result.get("start") or {}
        line = int(start.get("line") or 1)
        snippet = _read_line_snippet(path, line) if path and path.exists() else ""
        extra = result.get("extra") or {}
        findings.append(
            {
                "check_id": result.get("check_id"),
                "path": str(path.relative_to(target_path)) if path and path.is_relative_to(target_path) else result.get("path"),
                "line": line,
                "severity": extra.get("severity"),
                "message": extra.get("message"),
                "snippet": snippet,
            }
        )
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {"count": len(data.get("results", [])), "returned": len(findings), "by_severity": by_severity, "findings": findings}


def _semgrep_rule_yaml(rule_id: str, pattern: str, languages: list[str], message: str, severity: str) -> str:
    language_lines = "\n".join(f"      - {language}" for language in languages)
    escaped_message = message.replace('"', '\\"')
    return f"""rules:
  - id: {rule_id}
    message: "{escaped_message}"
    severity: {severity.upper()}
    languages:
{language_lines}
    pattern: |
      {pattern.replace(chr(10), chr(10) + '      ')}
"""


def _iter_source_files(target_path: Path, max_files: int = 5000):
    skipped = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
    for path in target_path.rglob("*"):
        if len(path.parts) and any(part in skipped for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in {ext for exts in _LANGUAGE_EXTENSIONS.values() for ext in exts}:
            yield path
            max_files -= 1
            if max_files <= 0:
                return


def _detect_languages(target_path: Path) -> list[str]:
    counts: dict[str, int] = {}
    for path in _iter_source_files(target_path, max_files=1000):
        for language, extensions in _LANGUAGE_EXTENSIONS.items():
            if path.suffix.lower() in extensions:
                counts[language] = counts.get(language, 0) + 1
    return sorted(counts, key=lambda item: counts[item], reverse=True)


def _map_api_endpoints(target_path: Path) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for path in _iter_source_files(target_path):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            for pattern in _ROUTE_PATTERNS:
                for match in pattern.finditer(line):
                    groups = match.groups()
                    if len(groups) >= 2 and groups[0].lower() in {"get", "post", "put", "patch", "delete", "options", "head"}:
                        method = groups[0].upper()
                        route = groups[1]
                    elif len(groups) >= 2:
                        method = groups[1].replace("'", "").replace('"', "")
                        route = groups[0]
                    else:
                        method = "UNKNOWN"
                        route = groups[0]
                    endpoints.append(
                        {
                            "method": method,
                            "route": route,
                            "path": str(path.relative_to(target_path)),
                            "line": idx,
                            "snippet": line.strip()[:300],
                        }
                    )
    return endpoints[:1000]


@dataclass
class StaticAnalysisService:
    """Bounded service for source ingest and local static-analysis tooling."""

    def check_environment(self) -> dict[str, Any]:
        return {
            "success": True,
            "tools": {
                "git": shutil.which("git"),
                "semgrep": shutil.which("semgrep"),
                "codeql": shutil.which("codeql"),
            },
            "workspace_root": str(_service_root()),
        }

    def ingest_code(self, source: str, source_type: str = "auto", destination_dir: str = "", timeout_seconds: int = 120) -> dict[str, Any]:
        if not source:
            return {"success": False, "error": "source is required"}
        source_type = (source_type or "auto").lower()
        if source_type == "auto":
            if source.endswith(".zip") or Path(source).suffix.lower() == ".zip":
                source_type = "zip"
            elif urlparse(source).scheme in {"http", "https", "ssh", "git"} or source.endswith(".git"):
                source_type = "git"
            else:
                source_type = "directory"
        destination = _resolve_path(destination_dir) if destination_dir else _default_workspace_for_source(source)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if source_type == "git":
            if destination.exists() and any(destination.iterdir()):
                return {"success": False, "error": f"destination already exists and is not empty: {destination}"}
            result = _run_command(["git", "clone", "--depth", "1", source, str(destination)], timeout_seconds=timeout_seconds)
            result["destination"] = str(destination)
            return result
        if source_type == "zip":
            zip_path = _resolve_path(source)
            if not zip_path.exists():
                return {"success": False, "error": f"zip file does not exist: {zip_path}"}
            try:
                extracted = _safe_extract_zip(zip_path, destination)
            except (OSError, zipfile.BadZipFile, ValueError) as exc:
                return {"success": False, "error": str(exc)}
            return {"success": True, "destination": str(destination), "extracted_preview": extracted}
        if source_type == "directory":
            src_path = _resolve_path(source)
            if not src_path.is_dir():
                return {"success": False, "error": f"directory does not exist: {src_path}"}
            if destination == src_path:
                return {"success": True, "destination": str(src_path), "copied": False}
            if destination.exists() and any(destination.iterdir()):
                return {"success": False, "error": f"destination already exists and is not empty: {destination}"}
            shutil.copytree(src_path, destination, dirs_exist_ok=True)
            return {"success": True, "destination": str(destination), "copied": True}
        return {"success": False, "error": f"unsupported source_type: {source_type}"}

    def semgrep_scan(self, target_path: str, semgrep_config: str = "auto", timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        target = _resolve_path(target_path)
        if not target.exists():
            return {"success": False, "error": f"target_path does not exist: {target}"}
        config = semgrep_config or "auto"
        result = _run_command(["semgrep", "--config", config, "--json", str(target)], timeout_seconds=timeout_seconds)
        if not result["success"] and "stdout" not in result:
            return result
        try:
            parsed = json.loads(result.get("stdout") or "{}")
        except json.JSONDecodeError as exc:
            result["parse_error"] = str(exc)
            return result
        result["summary"] = _summarize_semgrep_findings(parsed, target if target.is_dir() else target.parent)
        return result

    def write_semgrep_rule(
        self,
        rule_name: str,
        pattern: str,
        languages: list[str] | None = None,
        message: str = "Custom Hermes static-analysis finding",
        severity: str = "WARNING",
        output_path: str = "",
    ) -> dict[str, Any]:
        if not rule_name or not pattern:
            return {"success": False, "error": "rule_name and pattern are required"}
        languages = languages or ["python"]
        output = _resolve_path(output_path) if output_path else _service_root() / "rules" / f"{_safe_name(rule_name)}.yaml"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_semgrep_rule_yaml(_safe_name(rule_name), pattern, languages, message, severity), encoding="utf-8")
        return {"success": True, "rule_path": str(output), "scan_command": ["semgrep", "--config", str(output), "--json", "<target_path>"]}

    def map_api_endpoints(self, target_path: str) -> dict[str, Any]:
        target = _resolve_path(target_path)
        if not target.exists():
            return {"success": False, "error": f"target_path does not exist: {target}"}
        endpoints = _map_api_endpoints(target)
        return {"success": True, "endpoint_count": len(endpoints), "endpoints": endpoints}

    def codeql_plan(self, target_path: str, language: str = "", database_path: str = "") -> dict[str, Any]:
        target = _resolve_path(target_path)
        languages = [language] if language else _detect_languages(target)
        chosen = languages[0] if languages else "javascript"
        database = _resolve_path(database_path) if database_path else _service_root() / "codeql-dbs" / f"{_safe_name(target.name)}-{chosen}"
        return {
            "success": True,
            "detected_languages": languages,
            "database_path": str(database),
            "database_create_command": ["codeql", "database", "create", str(database), "--language", chosen, "--source-root", str(target)],
            "query_run_command": ["codeql", "database", "analyze", str(database), "<query.ql>", "--format", "sarif-latest", "--output", "results.sarif"],
            "recommended_queries": sorted(_CODEQL_TEMPLATES.keys()),
        }

    def codeql_database_create(self, target_path: str, language: str, database_path: str = "", timeout_seconds: int = 900) -> dict[str, Any]:
        plan = self.codeql_plan(target_path, language, database_path)
        result = _run_command(plan["database_create_command"], timeout_seconds=timeout_seconds)
        result.update({"database_path": plan["database_path"]})
        return result

    def write_codeql_query(self, query_type: str, language: str, output_path: str = "") -> dict[str, Any]:
        query_type = (query_type or "").lower()
        language = (language or "").lower()
        template = _CODEQL_TEMPLATES.get(query_type, {}).get(language)
        if not template:
            return {"success": False, "error": f"no template for query_type={query_type!r}, language={language!r}"}
        output = _resolve_path(output_path) if output_path else _service_root() / "codeql-queries" / f"{_safe_name(query_type)}-{_safe_name(language)}.ql"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(template, encoding="utf-8")
        return {"success": True, "query_path": str(output), "query_type": query_type, "language": language}

    def codeql_query_run(self, database_path: str, query_file: str, output_path: str = "", timeout_seconds: int = 900) -> dict[str, Any]:
        database = _resolve_path(database_path)
        query = _resolve_path(query_file)
        if not database.exists():
            return {"success": False, "error": f"database_path does not exist: {database}"}
        if not query.exists():
            return {"success": False, "error": f"query_file does not exist: {query}"}
        output = _resolve_path(output_path) if output_path else _service_root() / "codeql-results" / f"{_safe_name(database.name)}-{_safe_name(query.stem)}.sarif"
        output.parent.mkdir(parents=True, exist_ok=True)
        result = _run_command(
            ["codeql", "database", "analyze", str(database), str(query), "--format", "sarif-latest", "--output", str(output)],
            timeout_seconds=timeout_seconds,
        )
        result["output_path"] = str(output)
        return result


def static_analysis_service(
    action: str,
    target_path: str = "",
    source: str = "",
    source_type: str = "auto",
    destination_dir: str = "",
    semgrep_config: str = "auto",
    rule_name: str = "",
    pattern: str = "",
    languages: list[str] | None = None,
    message: str = "Custom Hermes static-analysis finding",
    severity: str = "WARNING",
    language: str = "",
    database_path: str = "",
    query_type: str = "",
    query_file: str = "",
    output_path: str = "",
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> str:
    service = StaticAnalysisService()
    try:
        if action == "check_environment":
            return _tool_response(service.check_environment())
        if action == "ingest_code":
            return _tool_response(service.ingest_code(source, source_type, destination_dir, timeout_seconds))
        if action == "semgrep_scan":
            return _tool_response(service.semgrep_scan(target_path, semgrep_config, timeout_seconds))
        if action == "write_semgrep_rule":
            return _tool_response(service.write_semgrep_rule(rule_name, pattern, languages, message, severity, output_path))
        if action == "map_api_endpoints":
            return _tool_response(service.map_api_endpoints(target_path))
        if action == "codeql_plan":
            return _tool_response(service.codeql_plan(target_path, language, database_path))
        if action == "codeql_database_create":
            return _tool_response(service.codeql_database_create(target_path, language, database_path, timeout_seconds))
        if action == "write_codeql_query":
            return _tool_response(service.write_codeql_query(query_type, language, output_path))
        if action == "codeql_query_run":
            return _tool_response(service.codeql_query_run(database_path, query_file, output_path, timeout_seconds))
        return _tool_response({"success": False, "error": f"unknown action: {action}"})
    except Exception as exc:
        return _tool_response({"success": False, "error": str(exc)})


STATIC_ANALYSIS_SCHEMA = {
    "name": "static_analysis_service",
    "description": (
        "Authorized static-analysis service for source ingest, Semgrep scanning/custom rule writing, "
        "API endpoint mapping, and CodeQL database/query scaffolding or execution. Use for defensive code review, "
        "variant analysis, and exploit-feasibility checks in code the operator is authorized to assess."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "check_environment",
                    "ingest_code",
                    "semgrep_scan",
                    "write_semgrep_rule",
                    "map_api_endpoints",
                    "codeql_plan",
                    "codeql_database_create",
                    "write_codeql_query",
                    "codeql_query_run",
                ],
            },
            "target_path": {"type": "string", "description": "Repository/file path to scan or plan against."},
            "source": {"type": "string", "description": "Git URL, zip file path, or source directory for ingest_code."},
            "source_type": {"type": "string", "enum": ["auto", "git", "zip", "directory"]},
            "destination_dir": {"type": "string", "description": "Optional destination for ingested code."},
            "semgrep_config": {"type": "string", "description": "Semgrep config value, e.g. auto, p/secrets, or a rule YAML path."},
            "rule_name": {"type": "string", "description": "Name/id for generated Semgrep rule."},
            "pattern": {"type": "string", "description": "Semgrep pattern body for generated rule."},
            "languages": {"type": "array", "items": {"type": "string"}, "description": "Semgrep languages for generated rule."},
            "message": {"type": "string", "description": "Finding message for generated Semgrep rule."},
            "severity": {"type": "string", "description": "Semgrep severity for generated rule."},
            "language": {"type": "string", "description": "CodeQL language, e.g. javascript, python, go, java."},
            "database_path": {"type": "string", "description": "CodeQL database path."},
            "query_type": {"type": "string", "enum": ["ssrf", "sql_injection", "path_traversal", "permission_change"]},
            "query_file": {"type": "string", "description": "CodeQL query file to run."},
            "output_path": {"type": "string", "description": "Output path for generated rules/queries or CodeQL results."},
            "timeout_seconds": {"type": "integer", "description": "Command timeout for local tool execution."},
        },
        "required": ["action"],
    },
}


registry.register(
    name="static_analysis_service",
    toolset="static_analysis",
    schema=STATIC_ANALYSIS_SCHEMA,
    handler=lambda args, **kw: static_analysis_service(
        action=args.get("action", ""),
        target_path=args.get("target_path", ""),
        source=args.get("source", ""),
        source_type=args.get("source_type", "auto"),
        destination_dir=args.get("destination_dir", ""),
        semgrep_config=args.get("semgrep_config", "auto"),
        rule_name=args.get("rule_name", ""),
        pattern=args.get("pattern", ""),
        languages=args.get("languages"),
        message=args.get("message", "Custom Hermes static-analysis finding"),
        severity=args.get("severity", "WARNING"),
        language=args.get("language", ""),
        database_path=args.get("database_path", ""),
        query_type=args.get("query_type", ""),
        query_file=args.get("query_file", ""),
        output_path=args.get("output_path", ""),
        timeout_seconds=args.get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS),
    ),
    emoji="🔎",
)
