from pathlib import Path
from typer.testing import CliRunner
from aegisskill.main import app

runner = CliRunner()


def test_cli_benign_skill_mock():
    fixtures_dir = Path(__file__).parent / "fixtures"
    benign_dir = fixtures_dir / "benign_skill"

    result = runner.invoke(app, ["scan", str(benign_dir), "--dry-run-mock"])
    assert result.exit_code == 0
    assert "SAFE TO LOAD" in result.output
    assert "json-formatter" in result.output


def test_cli_malicious_skill_mock():
    fixtures_dir = Path(__file__).parent / "fixtures"
    malicious_dir = fixtures_dir / "malicious_skill"

    result = runner.invoke(app, ["scan", str(malicious_dir), "--dry-run-mock"])
    assert result.exit_code == 1
    assert "THREAT DETECTED" in result.output
    assert "Data Exfiltration" in result.output or "BLOCKED" in result.output


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AegisSkill version" in result.output


def test_cli_setup(tmp_path, monkeypatch):
    mock_global_dir = tmp_path / "global_models"
    mock_global_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("aegisskill.main.get_global_model_dir", lambda: mock_global_dir)

    fake_gguf = tmp_path / "custom-gemma.gguf"
    fake_gguf.write_text("dummy model content")

    result = runner.invoke(app, ["setup", "--path", str(fake_gguf), "--copy"])
    assert result.exit_code == 0
    assert "Active Model Successfully Configured" in result.output
    assert (mock_global_dir / "active_model.gguf").exists()

