import json
import zipfile

from tools.static_analysis_tool import StaticAnalysisService, static_analysis_service


def test_write_semgrep_rule_creates_scan_command(tmp_path):
    output = tmp_path / "rule.yaml"
    payload = json.loads(
        static_analysis_service(
            action="write_semgrep_rule",
            rule_name="hardcoded-token",
            pattern='SECRET = "$VALUE"',
            languages=["python"],
            output_path=str(output),
        )
    )

    assert payload["success"] is True
    assert payload["rule_path"] == str(output.resolve())
    assert "hardcoded-token" in output.read_text(encoding="utf-8")
    assert payload["scan_command"][:3] == ["semgrep", "--config", str(output.resolve())]


def test_map_api_endpoints_detects_python_and_express_routes(tmp_path):
    (tmp_path / "app.py").write_text('@app.get("/api/projects/{id}")\ndef get_project(): pass\n', encoding="utf-8")
    (tmp_path / "routes.js").write_text('router.post("/api/login", handler)\n', encoding="utf-8")

    result = StaticAnalysisService().map_api_endpoints(str(tmp_path))

    routes = {(entry["method"], entry["route"]) for entry in result["endpoints"]}
    assert result["success"] is True
    assert ("GET", "/api/projects/{id}") in routes
    assert ("POST", "/api/login") in routes


def test_codeql_plan_detects_language_and_builds_commands(tmp_path):
    (tmp_path / "server.js").write_text("fetch(req.query.url)\n", encoding="utf-8")

    plan = StaticAnalysisService().codeql_plan(str(tmp_path))

    assert plan["success"] is True
    assert plan["detected_languages"] == ["javascript"]
    assert plan["database_create_command"][:3] == ["codeql", "database", "create"]
    assert "ssrf" in plan["recommended_queries"]


def test_write_codeql_query_uses_requested_template(tmp_path):
    output = tmp_path / "ssrf.ql"
    result = StaticAnalysisService().write_codeql_query("ssrf", "javascript", str(output))

    assert result["success"] is True
    assert result["query_path"] == str(output.resolve())
    assert "outbound request sink" in output.read_text(encoding="utf-8")


def test_ingest_zip_rejects_path_traversal(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.py", "print('bad')")

    result = StaticAnalysisService().ingest_code(str(archive), "zip", str(tmp_path / "out"))

    assert result["success"] is False
    assert "unsafe zip member" in result["error"]
