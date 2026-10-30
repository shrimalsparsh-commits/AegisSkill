"""Local LLM inference engine using llama-cpp-python with strict JSON schema enforcement."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schemas import SecurityReport, ThreatCategory


GLOBAL_CONFIG_DIR: Path = Path.home() / ".aegisskill"
GLOBAL_MODEL_DIR: Path = Path.home() / ".aegisskill" / "models"
ACTIVE_MODEL_NAME: str = "active_model.gguf"


def get_global_model_dir() -> Path:
    """Return the persistent global model directory ~/.aegisskill/models."""
    GLOBAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    return GLOBAL_MODEL_DIR


def resolve_dynamic_model_path(
    explicit_path: Optional[Path] = None,
    fast_mode: bool = False,
) -> Path:
    """Dynamically resolve model path in priority order:

    1. Explicit path if provided.
    2. Global directory active_model.gguf (~/.aegisskill/models/active_model.gguf).
    3. Any .gguf in ~/.aegisskill/models/ (if fast_mode, prefer fast model or 1st .gguf).
    4. Local workspace candidates (e.g. aegisskill/.models/, .models/, models/).
    """
    if explicit_path is not None:
        return explicit_path

    # 1. Check persistent global model directory ~/.aegisskill/models/
    global_dir = Path.home() / ".aegisskill" / "models"
    if global_dir.exists():
        active = global_dir / ACTIVE_MODEL_NAME
        if active.exists():
            return active

        gguf_files = list(global_dir.glob("*.gguf"))
        if gguf_files:
            if fast_mode:
                fast_candidates = [
                    f for f in gguf_files if "1.5b" in f.name.lower() or "fast" in f.name.lower()
                ]
                if fast_candidates:
                    return fast_candidates[0]
            return gguf_files[0]

    # 2. Check local workspace candidates (relative to current working directory)
    if fast_mode:
        local_fast = [
            Path("models") / ModelConfig.FAST_MODEL,
            Path(".models") / ModelConfig.FAST_MODEL,
            Path("aegisskill/.models") / ModelConfig.FAST_MODEL,
        ]
        for p in local_fast:
            if p.exists():
                return p
        return local_fast[0]

    local_candidates = [
        Path("aegisskill/.models/qwen3-8b.gguf"),
        Path(".models/qwen3-8b.gguf"),
        Path("models/qwen3-8b.gguf"),
        Path("models") / ModelConfig.DEFAULT_QWEN3_MODEL,
        Path(".models") / ModelConfig.DEFAULT_QWEN3_MODEL,
    ]
    for p in local_candidates:
        if p.exists():
            return p

    # Default fallback pointing to active_model.gguf in global dir
    return global_dir / ACTIVE_MODEL_NAME


@dataclass
class ModelConfig:
    """Configuration for local model loading."""

    model_path: Path
    n_ctx: int = 2048  # Strict 2048 limit to prevent VRAM exhaustion on 6GB GPUs
    n_gpu_layers: int = -1  # Offload layers to GPU if available; falls back to CPU
    temperature: float = 0.1
    fast_mode: bool = False
    dry_run_mock: bool = False

    # Default model filenames
    DEFAULT_QWEN3_MODEL: str = "qwen3-8b-instruct.gguf"
    FAST_MODEL: str = "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"


class InferenceEngine:
    """Orchestrates local GGUF model loading and structured JSON inference."""

    SYSTEM_PROMPT = """You are AegisSkill, a Staff-Level Python Security Architect analyzing AI Agent Skills.
Your job is to detect malicious "Skill-Inject" supply chain attacks, data exfiltration, stealth backdoors, and credential theft.

You will be given:
1. The skill's stated name and intended purpose (from SKILL.md).
2. The deterministic AST nodes extracted from the skill's Python files (imports, function signatures, network calls, OS calls, environment access).

Analyze whether the code's behavior aligns with its stated purpose or if it introduces malicious or unauthorized capabilities (e.g. reading os.environ, contacting remote servers, executing shell commands).

You MUST respond strictly in valid JSON adhering to this schema:
{
  "is_safe": boolean,
  "threat_category": "None" | "Data Exfiltration" | "Destructive I/O" | "Arbitrary Code Execution" | "Credential Theft" | "Skill-Inject Supply Chain Attack",
  "vulnerability_explanation": "string explaining findings"
}
"""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self._llm = None

        if not self.config.dry_run_mock:
            self._init_llm()

    def _init_llm(self) -> None:
        """Dynamically load llama-cpp-python model with strict context constraints."""
        if not self.config.model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at: {self.config.model_path}\n"
                f"No active GGUF model configured in ~/.aegisskill/models/ or found in local paths.\n"
                f"Please run 'aegis setup --path <path-to-gguf>' to link your local model (e.g. Qwen3 or Gemma 3),\n"
                f"pass '--model-path <path>', or use '--dry-run-mock' for testing."
            )

        try:
            from llama_cpp import Llama
        except ImportError as exc:
            raise ImportError(
                "llama-cpp-python is not installed. Run 'pip install llama-cpp-python' or use '--dry-run-mock'."
            ) from exc

        # Initialize local GGUF model with strict n_ctx
        self._llm = Llama(
            model_path=str(self.config.model_path),
            n_ctx=self.config.n_ctx,
            n_gpu_layers=self.config.n_gpu_layers,
            verbose=False,
        )

    def analyze(self, prompt_content: str, is_known_malicious_fixture: Optional[bool] = None) -> SecurityReport:
        """Run analysis on the extracted context and return a verified SecurityReport."""
        # 1. Fallback / Mock mode for demo and hackathon reliability
        if self.config.dry_run_mock:
            return self._generate_mock_report(prompt_content, is_known_malicious_fixture)

        if self._llm is None:
            raise RuntimeError("Inference engine was not initialized properly.")

        # 2. Live Local LLM inference with native JSON schema enforcement
        schema = SecurityReport.model_json_schema()
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": prompt_content},
        ]

        try:
            response = self._llm.create_chat_completion(
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=512,
                response_format={
                    "type": "json_object",
                    "schema": schema,
                },
            )

            raw_text = response["choices"][0]["message"]["content"]
            return self._parse_and_validate_json(raw_text)

        except Exception as exc:
            # Secondary fallback if grammar or driver had an issue
            raise RuntimeError(f"Error executing local model inference: {exc}") from exc

    def _parse_and_validate_json(self, raw_json_text: str) -> SecurityReport:
        """Parse raw response text with Pydantic validation."""
        try:
            cleaned = raw_json_text.strip()
            # If markdown fences are returned despite schema
            if cleaned.startswith("```json"):
                cleaned = cleaned.removeprefix("```json").removesuffix("```").strip()
            elif cleaned.startswith("```"):
                cleaned = cleaned.removeprefix("```").removesuffix("```").strip()

            data = json.loads(cleaned)
            return SecurityReport(**data)
        except Exception as err:
            return SecurityReport(
                is_safe=False,
                threat_category="Parsing Error",
                vulnerability_explanation=f"LLM produced malformed response: {err}. Raw output: {raw_json_text[:200]}",
            )

    def _generate_mock_report(self, prompt: str, hint_malicious: Optional[bool]) -> SecurityReport:
        """Generate deterministic mock report for test fixtures and hackathon fallback."""
        lower_prompt = prompt.lower()

        # Check for clear indicators in prompt
        has_exfil = "os.environ" in prompt or "urllib" in lower_prompt or "attacker-telemetry" in lower_prompt
        has_destructive = "rm -rf" in prompt or "shutil.rmtree" in prompt

        if hint_malicious is True or has_exfil or has_destructive:
            threat = ThreatCategory.DATA_EXFILTRATION.value if has_exfil else ThreatCategory.DESTRUCTIVE_IO.value
            explanation = (
                "[MOCK VERDICT] High-risk discrepancy detected: Stated skill documentation claims "
                "pure markdown processing, but AST reveals harvesting of sensitive environment variables "
                "via os.environ followed by unauthorized HTTP POST exfiltration to an external endpoint."
            )
            return SecurityReport(
                is_safe=False,
                threat_category=threat,
                vulnerability_explanation=explanation,
            )

        return SecurityReport(
            is_safe=True,
            threat_category=ThreatCategory.NONE.value,
            vulnerability_explanation=(
                "[MOCK VERDICT] All extracted AST nodes (imports and functions) strictly align "
                "with the skill's declared utility purpose. No network or destructive OS calls identified."
            ),
        )

