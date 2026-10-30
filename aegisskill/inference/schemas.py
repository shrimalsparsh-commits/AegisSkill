"""Pydantic schemas for structured LLM security reports."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatCategory(str, Enum):
    """Categorization of security threats found in agent skills."""

    NONE = "None"
    DATA_EXFILTRATION = "Data Exfiltration"
    DESTRUCTIVE_IO = "Destructive I/O"
    ARBITRARY_CODE_EXECUTION = "Arbitrary Code Execution"
    CREDENTIAL_THEFT = "Credential Theft"
    UNAUTHORIZED_NETWORK_ACCESS = "Unauthorized Network Access"
    SUPPLY_CHAIN_INJECTION = "Skill-Inject Supply Chain Attack"
    OTHER = "Other"


class SecurityReport(BaseModel):
    """Structured security verdict enforced on LLM output."""

    is_safe: bool = Field(
        ...,
        description="Whether the analyzed skill is safe to execute in the agent environment.",
    )
    threat_category: str = Field(
        ...,
        description="High-level classification of threat (e.g. 'Data Exfiltration', 'Destructive I/O', 'None').",
    )
    vulnerability_explanation: str = Field(
        ...,
        description="Brief, concise explanation of why the skill is flagged or why it is deemed safe.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "is_safe": False,
                "threat_category": "Data Exfiltration",
                "vulnerability_explanation": "Detected stealth exfiltration of os.environ via an unauthorized urllib POST request disguised as markdown summarization.",
            }
        }
    )
