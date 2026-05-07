import json

from tools.saas_security_tool import ContextAwareFuzzer, TrafficAnalyzer, _records_from_json, saas_bola_assess


def test_traffic_analyzer_extracts_ids_and_graphql(tmp_path):
    traffic = [
        {
            "method": "POST",
            "url": "https://app.example.test/graphql",
            "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
            "body": {"operationName": "Project", "query": "query Project($id: ID!){ project(id:$id){ id orgId } }", "variables": {"id": "123e4567-e89b-12d3-a456-426614174000"}},
            "status_code": 200,
            "response_body": {"data": {"project": {"id": "123e4567-e89b-12d3-a456-426614174000", "orgId": "org_abc"}}},
        }
    ]
    path = tmp_path / "traffic.json"
    path.write_text(json.dumps(traffic), encoding="utf-8")

    result = TrafficAnalyzer.from_file(path).analyze()

    assert result["success"] is True
    assert result["summary"]["replay_candidates"] == 1
    endpoint = result["endpoints"][0]
    assert endpoint["graphql"]["operation_name"] == "Project"
    assert endpoint["headers"]["Authorization"] == "<redacted>"
    assert "123e4567-e89b-12d3-a456-426614174000" in result["id_index"]


def test_har_records_are_supported():
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://app.example.test/api/projects/123e4567-e89b-12d3-a456-426614174000", "headers": []},
                    "response": {"status": 200, "content": {"text": "{}"}},
                }
            ]
        }
    }
    records = _records_from_json(har)
    assert len(records) == 1
    assert records[0].method == "GET"


def test_compare_replay_results_flags_possible_bola():
    result = ContextAwareFuzzer.compare_results(
        {"status_code": 200, "body": {"id": "obj-1"}},
        {"status_code": 200, "body": {"id": "obj-1", "name": "leaked"}},
        ["obj-1"],
    )
    assert result["possible_bola"] is True
    assert result["matched_object_ids_in_alternate_response"] == ["obj-1"]


def test_tool_builds_replay_plan(tmp_path):
    traffic = [
        {
            "method": "GET",
            "url": "https://app.example.test/api/projects/123e4567-e89b-12d3-a456-426614174000",
            "status_code": 200,
        }
    ]
    path = tmp_path / "traffic.json"
    path.write_text(json.dumps(traffic), encoding="utf-8")

    payload = json.loads(saas_bola_assess(action="build_replay_plan", traffic_file=str(path)))
    assert payload["success"] is True
    assert payload["candidate_count"] == 1
