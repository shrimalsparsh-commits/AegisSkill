"""Parser for SKILL.md frontmatter and markdown documentation."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import yaml


@dataclass
class SkillMetadata:
    """Parsed metadata and documentation of an Agent Skill."""

    name: str = "unknown-skill"
    description: str = ""
    instructions: str = ""
    raw_frontmatter: Dict[str, Any] = field(default_factory=dict)
    file_path: Optional[Path] = None

    def to_prompt_context(self) -> str:
        """Format metadata into a clean summary for LLM context."""
        return (
            f"Skill Name: {self.name}\n"
            f"Stated Description: {self.description.strip() or 'None provided'}\n"
            f"Instructions / Intended Workflow:\n{self.instructions.strip() or 'None provided'}"
        )


def parse_skill_markdown(skill_path: Path) -> SkillMetadata:
    """Parse SKILL.md in the given directory or direct file path.

    Extracts YAML frontmatter (name, description, etc.) and markdown instructions.
    """
    skill_file = skill_path if skill_path.is_file() else skill_path / "SKILL.md"

    if not skill_file.exists():
        return SkillMetadata(
            name=skill_path.name,
            description="No SKILL.md found in target directory.",
            instructions="",
            file_path=None,
        )

    content = skill_file.read_text(encoding="utf-8", errors="replace")
    frontmatter_dict: Dict[str, Any] = {}
    instructions = content

    # Check for YAML frontmatter denoted by leading `---`
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            raw_yaml = parts[1]
            instructions = parts[2].strip()
            try:
                loaded = yaml.safe_load(raw_yaml)
                if isinstance(loaded, dict):
                    frontmatter_dict = loaded
            except yaml.YAMLError:
                # If frontmatter YAML is malformed, fall back to whole content
                instructions = content

    name = str(frontmatter_dict.get("name") or skill_path.name)
    description = str(frontmatter_dict.get("description") or "")

    return SkillMetadata(
        name=name,
        description=description,
        instructions=instructions,
        raw_frontmatter=frontmatter_dict,
        file_path=skill_file,
    )

