import json

from agent.trajectory_reducer import TrajectoryReductionConfig, reduce_messages_for_api


def _assistant_call(call_id, name, args):
    return {
        "role": "assistant",
        "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}],
    }


def _tool(call_id, payload):
    return {"role": "tool", "tool_call_id": call_id, "content": json.dumps(payload)}


def test_reducer_summarizes_verbose_successful_terminal_output_without_mutating_original():
    original = [
        _assistant_call("c1", "terminal", {"command": "make"}),
        _tool("c1", {"output": "compiled\n" * 300, "exit_code": 0, "error": None}),
    ]

    reduced = reduce_messages_for_api(original, TrajectoryReductionConfig(min_success_output_chars=100))
    payload = json.loads(reduced[1]["content"])

    assert payload["trajectory_reduced"] is True
    assert payload["output"].startswith("[Execution Successful")
    assert payload["output_summary"]["lines"] == 300
    assert "compiled" in json.loads(original[1]["content"])["output"]


def test_reducer_keeps_error_output_for_debugging():
    messages = [
        _assistant_call("c1", "terminal", {"command": "gcc exploit.c"}),
        _tool("c1", {"output": "error: missing header\n" * 100, "exit_code": 1, "error": None}),
    ]

    reduced = reduce_messages_for_api(messages, TrajectoryReductionConfig(min_success_output_chars=100))

    assert "missing header" in json.loads(reduced[1]["content"])["output"]
    assert "trajectory_reduced" not in json.loads(reduced[1]["content"])


def test_reducer_purges_superseded_search_failures():
    messages = [
        _assistant_call("c1", "terminal", {"command": "rg SECRET file1"}),
        _tool("c1", {"output": "", "exit_code": 1, "error": None}),
        _assistant_call("c2", "terminal", {"command": "rg SECRET config.php"}),
        _tool("c2", {"output": "config.php:SECRET=redacted", "exit_code": 0, "error": None}),
    ]

    reduced = reduce_messages_for_api(messages)

    assert "superseded" in json.loads(reduced[1]["content"])["output"]
    assert "config.php" in json.loads(reduced[3]["content"])["output"]


def test_reducer_purges_file_read_superseded_by_edit():
    messages = [
        _assistant_call("c1", "read_file", {"path": "app.py"}),
        _tool("c1", {"content": "old app contents", "success": True}),
        _assistant_call("c2", "patch", {"path": "app.py", "diff": "..."}),
        _tool("c2", {"success": True, "diff": "--- old\n+++ new"}),
    ]

    reduced = reduce_messages_for_api(messages)

    assert "superseded" in json.loads(reduced[1]["content"])["content"]


def test_reducer_config_parses_false_strings():
    config = TrajectoryReductionConfig.from_mapping({"enabled": "false", "min_success_output_chars": "not-an-int"})

    assert config.enabled is False
    assert config.min_success_output_chars == 1200
