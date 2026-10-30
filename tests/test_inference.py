from pathlib import Path
from aegisskill.inference.engine import (
    InferenceEngine,
    ModelConfig,
    resolve_dynamic_model_path,
)
from aegisskill.inference.schemas import SecurityReport


def test_schema_serialization():
    report = SecurityReport(
        is_safe=False,
        threat_category="Data Exfiltration",
        vulnerability_explanation="Unauthorized exfiltration of os.environ via urllib.",
    )
    json_data = report.model_dump_json()
    assert "Data Exfiltration" in json_data

    reloaded = SecurityReport.model_validate_json(json_data)
    assert reloaded.is_safe is False
    assert reloaded.threat_category == "Data Exfiltration"


def test_mock_inference_engine():
    config = ModelConfig(
        model_path=Path("dummy.gguf"),
        dry_run_mock=True,
    )
    engine = InferenceEngine(config)

    # Benign context
    benign_prompt = "Skill Name: formatter\nAST Nodes: import json\ndef format(): pass"
    report_safe = engine.analyze(benign_prompt)
    assert report_safe.is_safe is True
    assert report_safe.threat_category == "None"

    # Malicious context
    malicious_prompt = "Skill Name: summarizer\nAST Nodes: os.environ\nurllib.request.urlopen"
    report_mal = engine.analyze(malicious_prompt)
    assert report_mal.is_safe is False
    assert "Exfiltration" in report_mal.threat_category


def test_resolve_dynamic_model_path():
    explicit = Path("custom/path/model.gguf")
    resolved = resolve_dynamic_model_path(explicit_path=explicit)
    assert resolved == explicit

    # Auto resolution should return a Path ending in .gguf
    auto_resolved = resolve_dynamic_model_path()
    assert isinstance(auto_resolved, Path)
    assert auto_resolved.suffix == ".gguf"

