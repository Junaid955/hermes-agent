"""Pre-LLM trajectory reduction middleware.

The reducer operates only on the per-request API message copy. It never mutates
Hermes' stored transcript, session DB rows, tool logs, or UI-visible history.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any

_SUCCESS_PLACEHOLDER = "[Execution Successful: exit_code=0; verbose stdout summarized by trajectory reduction]"
_SEARCH_SUPERSEDED = "[System: Earlier search attempt produced no useful matches and was superseded by a later successful search.]"
_FILE_SUPERSEDED = "[System: Earlier file snapshot superseded by a later edit; use the later diff/current file state.]"

_SEARCH_RE = re.compile(r"(^|\s)(rg|grep|ag|ack)\b")
_FILE_ARG_KEYS = ("path", "file_path", "filepath", "target_file", "filename")
_EDIT_TOOL_NAMES = {"write_file", "patch", "edit_file", "apply_patch"}
_READ_TOOL_NAMES = {"read_file"}


@dataclass(frozen=True)
class TrajectoryReductionConfig:
    enabled: bool = True
    summarize_successful_tool_output: bool = True
    purge_superseded_searches: bool = True
    purge_superseded_file_reads: bool = True
    min_success_output_chars: int = 1200

    @classmethod
    def from_mapping(cls, value: Any) -> "TrajectoryReductionConfig":
        if not isinstance(value, dict):
            return cls()
        return cls(
            enabled=bool(value.get("enabled", True)),
            summarize_successful_tool_output=bool(value.get("summarize_successful_tool_output", True)),
            purge_superseded_searches=bool(value.get("purge_superseded_searches", True)),
            purge_superseded_file_reads=bool(value.get("purge_superseded_file_reads", True)),
            min_success_output_chars=max(0, int(value.get("min_success_output_chars", 1200) or 0)),
        )


@dataclass
class _ToolMeta:
    name: str = ""
    args: dict[str, Any] | None = None


def reduce_messages_for_api(messages: list[dict[str, Any]], config: TrajectoryReductionConfig | None = None) -> list[dict[str, Any]]:
    """Return an API-safe reduced copy of *messages*.

    The reducer targets three high-waste patterns:
    - verbose successful tool output that does not need raw stdout replay;
    - earlier failed/no-hit search attempts superseded by a later hit;
    - stale file snapshots superseded by later edits to the same path.
    """
    cfg = config or TrajectoryReductionConfig()
    if not cfg.enabled:
        return messages

    reduced = copy.deepcopy(messages)
    tool_meta = _collect_tool_meta(reduced)

    if cfg.purge_superseded_searches:
        _purge_superseded_search_attempts(reduced, tool_meta)
    if cfg.purge_superseded_file_reads:
        _purge_superseded_file_reads(reduced, tool_meta)
    if cfg.summarize_successful_tool_output:
        _summarize_successful_outputs(reduced, tool_meta, cfg.min_success_output_chars)

    return reduced


def _collect_tool_meta(messages: list[dict[str, Any]]) -> dict[str, _ToolMeta]:
    meta: dict[str, _ToolMeta] = {}
    for message in messages:
        if message.get("role") != "assistant":
            continue
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            call_id = str(tool_call.get("id") or tool_call.get("call_id") or "")
            function = tool_call.get("function") or {}
            name = str(function.get("name") or "")
            args = _parse_json_maybe(function.get("arguments"))
            if call_id:
                meta[call_id] = _ToolMeta(name=name, args=args if isinstance(args, dict) else {})
    return meta


def _parse_json_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _tool_payload(message: dict[str, Any]) -> dict[str, Any] | None:
    content = message.get("content")
    parsed = _parse_json_maybe(content)
    return parsed if isinstance(parsed, dict) else None


def _set_tool_payload(message: dict[str, Any], payload: dict[str, Any]) -> None:
    message["content"] = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _meta_for_tool_message(message: dict[str, Any], tool_meta: dict[str, _ToolMeta]) -> _ToolMeta:
    return tool_meta.get(str(message.get("tool_call_id") or message.get("call_id") or ""), _ToolMeta())


def _command_for(meta: _ToolMeta) -> str:
    args = meta.args or {}
    return str(args.get("command") or args.get("cmd") or "")


def _is_search_command(command: str) -> bool:
    return bool(_SEARCH_RE.search(command))


def _has_useful_output(payload: dict[str, Any]) -> bool:
    output = str(payload.get("output") or payload.get("stdout") or "")
    return bool(output.strip())


def _is_success(payload: dict[str, Any]) -> bool:
    code = payload.get("exit_code", payload.get("returncode", payload.get("status_code")))
    error = payload.get("error")
    return code in (0, "0", None) and not error


def _purge_superseded_search_attempts(messages: list[dict[str, Any]], tool_meta: dict[str, _ToolMeta]) -> None:
    seen_later_success = False
    for message in reversed(messages):
        if message.get("role") != "tool":
            continue
        meta = _meta_for_tool_message(message, tool_meta)
        command = _command_for(meta)
        if meta.name != "terminal" or not _is_search_command(command):
            continue
        payload = _tool_payload(message)
        if not payload:
            continue
        if _is_success(payload) and _has_useful_output(payload):
            seen_later_success = True
            continue
        if seen_later_success:
            _set_tool_payload(message, {"output": _SEARCH_SUPERSEDED, "exit_code": payload.get("exit_code", 0), "error": None, "trajectory_reduced": True})


def _file_path_from_args(args: dict[str, Any] | None) -> str:
    if not isinstance(args, dict):
        return ""
    for key in _FILE_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _purge_superseded_file_reads(messages: list[dict[str, Any]], tool_meta: dict[str, _ToolMeta]) -> None:
    edited_paths: set[str] = set()
    for message in reversed(messages):
        if message.get("role") == "assistant":
            for tool_call in message.get("tool_calls") or []:
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function") or {}
                name = str(function.get("name") or "")
                args = _parse_json_maybe(function.get("arguments"))
                path = _file_path_from_args(args if isinstance(args, dict) else {})
                if name in _EDIT_TOOL_NAMES and path:
                    edited_paths.add(path)
            continue
        if message.get("role") != "tool":
            continue
        meta = _meta_for_tool_message(message, tool_meta)
        path = _file_path_from_args(meta.args)
        if meta.name in _READ_TOOL_NAMES and path and path in edited_paths:
            payload = _tool_payload(message)
            if isinstance(payload, dict):
                payload = {**payload, "content": _FILE_SUPERSEDED, "output": _FILE_SUPERSEDED, "trajectory_reduced": True}
                _set_tool_payload(message, payload)
            else:
                message["content"] = _FILE_SUPERSEDED


def _summarize_successful_outputs(messages: list[dict[str, Any]], tool_meta: dict[str, _ToolMeta], min_chars: int) -> None:
    for message in messages:
        if message.get("role") != "tool":
            continue
        meta = _meta_for_tool_message(message, tool_meta)
        if meta.name not in {"terminal", "execute_code"}:
            continue
        payload = _tool_payload(message)
        if not payload or not _is_success(payload):
            continue
        output_key = "output" if "output" in payload else "stdout" if "stdout" in payload else ""
        if not output_key:
            continue
        output = str(payload.get(output_key) or "")
        if len(output) < min_chars or output.startswith("[System:"):
            continue
        payload["output_summary"] = {
            "chars": len(output),
            "lines": len(output.splitlines()),
            "command": _command_for(meta)[:240],
        }
        payload[output_key] = _SUCCESS_PLACEHOLDER
        payload["trajectory_reduced"] = True
        _set_tool_payload(message, payload)
