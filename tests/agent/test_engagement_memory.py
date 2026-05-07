import json

from agent.memory_manager import MemoryManager
from plugins.memory.engagement import EngagementMemoryProvider
from tests.agent.test_memory_provider import FakeMemoryProvider


def test_engagement_memory_records_temporal_state(tmp_path):
    provider = EngagementMemoryProvider()
    provider.initialize("sess-1", hermes_home=str(tmp_path), platform="cli")

    result = json.loads(provider.handle_tool_call("engagement_record", {
        "event_type": "port_state",
        "summary": "10.0.0.5 port 80 observed open",
        "entities": [{"id": "10.0.0.5", "type": "host", "state": "http-open"}],
        "relations": [{"source": "10.0.0.5", "relation": "exposes", "target": "tcp/80"}],
        "tags": ["recon"],
    }))

    assert result["success"] is True
    assert result["event"]["event_type"] == "port_state"

    state = json.loads(provider.handle_tool_call("engagement_state", {"entity": "10.0.0.5", "include_history": True}))
    assert state["success"] is True
    assert state["state"]["entities"]["10.0.0.5"]["state"] == "http-open"
    assert state["state"]["relations"][0]["target"] == "tcp/80"
    assert state["state"]["recent_events"][0]["summary"] == "10.0.0.5 port 80 observed open"


def test_engagement_timeline_filters_by_tag(tmp_path):
    provider = EngagementMemoryProvider()
    provider.initialize("sess-2", hermes_home=str(tmp_path), platform="cli")
    provider.handle_tool_call("engagement_record", {"event_type": "finding", "summary": "idor candidate", "tags": ["bola"]})
    provider.handle_tool_call("engagement_record", {"event_type": "note", "summary": "unrelated", "tags": ["notes"]})

    timeline = json.loads(provider.handle_tool_call("engagement_timeline", {"tag": "bola"}))

    assert timeline["count"] == 1
    assert timeline["events"][0]["summary"] == "idor candidate"


def test_engagement_memory_uses_runtime_backend_config(tmp_path):
    provider = EngagementMemoryProvider()
    provider.initialize("sess-3", hermes_home=str(tmp_path), platform="cli", engagement_config={"backend": "graphiti"})

    assert "Backend: graphiti" in provider.system_prompt_block()


def test_engagement_memory_mem0g_backend_queues_when_kuzu_unavailable(tmp_path):
    provider = EngagementMemoryProvider()
    provider.initialize("sess-4", hermes_home=str(tmp_path), platform="cli", engagement_config={"backend": "mem0g"})

    provider.handle_tool_call("engagement_record", {"event_type": "finding", "summary": "graph candidate"})

    queue = tmp_path / "engagement-memory" / "mirror-queue.jsonl"
    assert queue.exists()
    assert '"backend": "mem0g"' in queue.read_text(encoding="utf-8")


def test_core_engagement_memory_can_run_with_external_provider():
    manager = MemoryManager()
    engagement = FakeMemoryProvider("engagement")
    engagement.core_provider = True
    external = FakeMemoryProvider("mem0")
    second_external = FakeMemoryProvider("hindsight")

    manager.add_provider(engagement)
    manager.add_provider(external)
    manager.add_provider(second_external)

    assert [provider.name for provider in manager.providers] == ["engagement", "mem0"]
