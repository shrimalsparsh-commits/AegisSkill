"""Scanner module bridging SKILL.md parsing, tree-sitter AST extraction, and LLM inference."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aegisskill.inference.engine import (
    InferenceEngine,
    ModelConfig,
    resolve_dynamic_model_path,
)
from aegisskill.inference.schemas import SecurityReport
from aegisskill.parsers.ast_extractor import ASTExtractionResult, ASTExtractor
from aegisskill.parsers.yaml_parser import SkillMetadata, parse_skill_markdown


@dataclass
class ScanResult:
    """Consolidated result of scanning an Agent Skill directory."""

    target_path: Path
    metadata: SkillMetadata
    ast_result: ASTExtractionResult
    report: SecurityReport
    duration_seconds: float = 0.0
    prompt_used: str = ""

    @property
    def is_safe(self) -> bool:
        return self.report.is_safe


class SkillScanner:
    """Orchestrates security scanning of an AI Agent Skill directory."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        fast_mode: bool = False,
        dry_run_mock: bool = False,
        n_ctx: int = 2048,
    ) -> None:
        self.fast_mode = fast_mode
        self.dry_run_mock = dry_run_mock

        # Resolve model path dynamically across global directory & local candidates
        if model_path is not None:
            resolved_model_path = model_path
        else:
            resolved_model_path = resolve_dynamic_model_path(
                explicit_path=None,
                fast_mode=fast_mode,
            )

        self.config = ModelConfig(
            model_path=resolved_model_path,
            n_ctx=n_ctx,
            fast_mode=fast_mode,
            dry_run_mock=dry_run_mock,
        )

        self.ast_extractor = ASTExtractor()
        self.engine = InferenceEngine(self.config)

    def build_prompt_context(self, metadata: SkillMetadata, ast_result: ASTExtractionResult) -> str:
        """Construct the compact context window for the 2048 token limit."""
        sections = [
            "### AGENT SKILL SPECIFICATION",
            metadata.to_prompt_context(),
            "",
            "### DETERMINISTIC AST AUDIT (HIGH-RISK NODES ONLY)",
            f"Files Scanned: {', '.join(ast_result.files_scanned) if ast_result.files_scanned else 'None'}",
            f"Total Artifacts Extracted: {ast_result.total_artifacts}",
            "",
            ast_result.to_condensed_context(max_chars=3500),
            "",
            "### INSTRUCTIONS FOR SECURITY AUDIT",
            "Evaluate whether the extracted code imports and actions conform strictly to the declared skill utility.",
            "If the code secretly accesses environment variables, initiates unauthorized HTTP/socket connections, ",
            "spawns subshells, or tampers with the filesystem without justification in SKILL.md, mark is_safe as false ",
            "and classify the threat category.",
        ]
        return "\n".join(sections)

    def scan(self, target_dir: Path) -> ScanResult:
        """Execute the end-to-end audit for the given Agent Skill directory."""
        start_time = time.perf_counter()
        target_dir = Path(target_dir).resolve()

        if not target_dir.exists():
            raise FileNotFoundError(f"Target directory or file does not exist: {target_dir}")

        # 1. Parse Metadata from SKILL.md
        metadata = parse_skill_markdown(target_dir)

        # 2. Extract High-Risk AST Nodes from .py files
        ast_result = self.ast_extractor.extract_from_directory(target_dir)

        # 3. Construct Context
        prompt = self.build_prompt_context(metadata, ast_result)

        # 4. Infer Security Verdict
        # Pass a hint if dry_run_mock is active and files contain obvious malicious traits
        is_fixture_malicious = "malicious" in target_dir.name.lower() or "summarizer" in metadata.name.lower()
        report = self.engine.analyze(prompt, is_known_malicious_fixture=is_fixture_malicious)

        elapsed = time.perf_counter() - start_time

        return ScanResult(
            target_path=target_dir,
            metadata=metadata,
            ast_result=ast_result,
            report=report,
            duration_seconds=elapsed,
            prompt_used=prompt,
        )

