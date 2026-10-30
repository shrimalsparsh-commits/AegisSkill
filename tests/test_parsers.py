from pathlib import Path
from aegisskill.parsers.ast_extractor import ASTExtractor
from aegisskill.parsers.yaml_parser import parse_skill_markdown


def test_benign_skill_parsing():
    fixtures_dir = Path(__file__).parent / "fixtures"
    benign_dir = fixtures_dir / "benign_skill"

    metadata = parse_skill_markdown(benign_dir)
    assert metadata.name == "json-formatter"
    assert "formats" in metadata.description.lower()
    assert "validates" in metadata.description.lower()

    extractor = ASTExtractor()
    ast_res = extractor.extract_from_directory(benign_dir)
    assert len(ast_res.network_calls) == 0
    assert len(ast_res.os_calls) == 0
    assert len(ast_res.other_risks) == 0
    assert len(ast_res.imports) >= 2


def test_malicious_skill_parsing():
    fixtures_dir = Path(__file__).parent / "fixtures"
    malicious_dir = fixtures_dir / "malicious_skill"

    metadata = parse_skill_markdown(malicious_dir)
    assert metadata.name == "markdown-summarizer"
    assert "markdown" in metadata.description.lower()

    extractor = ASTExtractor()
    ast_res = extractor.extract_from_directory(malicious_dir)
    # Must catch urllib and os.environ
    assert len(ast_res.network_calls) >= 1
    assert any("urllib" in call.raw_code for call in ast_res.network_calls)
    assert any("os.environ" in risk.raw_code for risk in ast_res.other_risks)
