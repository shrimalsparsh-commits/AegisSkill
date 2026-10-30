"""Deterministic AST extraction using tree-sitter and tree-sitter-python.

Extracts only high-risk AST nodes (imports, function signatures, network calls,
and OS/process interactions) rather than sending entire source files to the LLM.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser, Query, QueryCursor


@dataclass
class HighRiskArtifact:
    """An extracted AST artifact identified as security-relevant."""

    category: str  # "IMPORT", "FUNCTION_DEF", "NETWORK_CALL", "OS_CALL", "ENV_ACCESS"
    source_file: str
    line_number: int
    raw_code: str
    risk_level: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    details: str = ""

    def to_summary_line(self) -> str:
        """Formatted line for security audit and LLM prompt."""
        prefix = f"[{self.category}|{self.risk_level}]"
        return f"{prefix} {self.source_file}:{self.line_number} -> {self.raw_code.strip()}"


@dataclass
class ASTExtractionResult:
    """Aggregated AST extraction result across files in a skill."""

    files_scanned: List[str] = field(default_factory=list)
    imports: List[HighRiskArtifact] = field(default_factory=list)
    functions: List[HighRiskArtifact] = field(default_factory=list)
    network_calls: List[HighRiskArtifact] = field(default_factory=list)
    os_calls: List[HighRiskArtifact] = field(default_factory=list)
    other_risks: List[HighRiskArtifact] = field(default_factory=list)

    @property
    def total_artifacts(self) -> int:
        return (
            len(self.imports)
            + len(self.functions)
            + len(self.network_calls)
            + len(self.os_calls)
            + len(self.other_risks)
        )

    def to_condensed_context(self, max_chars: int = 4000) -> str:
        """Produce a condensed string of high-risk nodes to respect the 2048 token window."""
        sections: List[str] = []

        # High priority 1: Network & OS calls & Sensitive Env Access
        critical_items = self.network_calls + self.os_calls + self.other_risks
        if critical_items:
            sections.append("### High-Risk Network & OS Calls Detected in AST:")
            for item in critical_items:
                sections.append(item.to_summary_line())

        # High priority 2: Imports
        if self.imports:
            sections.append("\n### Module Imports:")
            for item in self.imports:
                sections.append(item.to_summary_line())

        # High priority 3: Function Declarations
        if self.functions:
            sections.append("\n### Function Signatures:")
            for item in self.functions:
                sections.append(item.to_summary_line())

        combined = "\n".join(sections)
        if len(combined) > max_chars:
            return combined[:max_chars] + f"\n... [Truncated {len(combined) - max_chars} chars for context limits]"
        return combined


class ASTExtractor:
    """Deterministic parser that extracts high-risk AST nodes from Python source code."""

    # Known high-risk patterns
    NETWORK_MODULES: Set[str] = {
        "requests", "urllib", "urllib3", "http", "http.client", "httpx",
        "aiohttp", "socket", "ftplib", "smtplib", "imaplib", "poplib",
        "websocket", "websockets", "paramiko", "telnetlib", "curl"
    }

    OS_EXEC_MODULES: Set[str] = {
        "os", "subprocess", "sys", "shutil", "posix", "winreg", "pty", "commands"
    }

    OS_EXEC_CALLS: Set[str] = {
        "system", "popen", "exec", "execl", "execle", "execlp", "execv",
        "execve", "execvp", "spawn", "spawnl", "spawnv", "fork",
        "kill", "remove", "unlink", "rmdir", "chmod", "chown"
    }

    SUBPROCESS_CALLS: Set[str] = {
        "run", "call", "check_call", "check_output", "Popen"
    }

    DANGEROUS_BUILTINS: Set[str] = {
        "eval", "exec", "__import__", "compile", "open"
    }

    TS_QUERY = """
    (import_statement) @import_stmt
    (import_from_statement) @import_from_stmt
    (function_definition
        name: (identifier) @func_name
        parameters: (parameters) @func_params) @func_def
    (call
        function: [(identifier) (attribute)] @call_target) @call_node
    (attribute
        object: (identifier) @attr_obj
        attribute: (identifier) @attr_name) @attr_node
    """

    def __init__(self) -> None:
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)
        self.query = Query(self.language, self.TS_QUERY)

    def extract_from_file(self, file_path: Path) -> List[HighRiskArtifact]:
        """Extract high-risk AST nodes from a single Python file."""
        if not file_path.exists() or file_path.suffix != ".py":
            return []

        try:
            source_bytes = file_path.read_bytes()
        except Exception:
            return []

        tree = self.parser.parse(source_bytes)
        cursor = QueryCursor(self.query)
        captures: Dict[str, List[Node]] = cursor.captures(tree.root_node)

        artifacts: List[HighRiskArtifact] = []
        rel_path = file_path.name

        # 1. Imports
        for node in captures.get("import_stmt", []) + captures.get("import_from_stmt", []):
            code_snippet = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            risk = "MEDIUM" if any(net in code_snippet for net in self.NETWORK_MODULES) or any(os_m in code_snippet for os_m in self.OS_EXEC_MODULES) else "LOW"
            artifacts.append(
                HighRiskArtifact(
                    category="IMPORT",
                    source_file=rel_path,
                    line_number=node.start_point.row + 1,
                    raw_code=code_snippet.strip(),
                    risk_level=risk,
                    details="Module import",
                )
            )

        # 2. Function definitions
        for node in captures.get("func_def", []):
            start_line = node.start_point.row
            # Grab just the def line (header) rather than the entire body
            code_line = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").splitlines()[0]
            artifacts.append(
                HighRiskArtifact(
                    category="FUNCTION_DEF",
                    source_file=rel_path,
                    line_number=start_line + 1,
                    raw_code=code_line.strip(),
                    risk_level="LOW",
                    details="Function definition header",
                )
            )

        # 3. Sensitive Attributes (e.g., os.environ)
        for node in captures.get("attr_node", []):
            attr_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
            if attr_text in {"os.environ", "environ", "sys.argv"}:
                artifacts.append(
                    HighRiskArtifact(
                        category="ENV_ACCESS",
                        source_file=rel_path,
                        line_number=node.start_point.row + 1,
                        raw_code=attr_text,
                        risk_level="HIGH",
                        details="Access to environment variables or process secrets",
                    )
                )

        # 4. Function and Method Calls
        for node in captures.get("call_node", []):
            call_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
            # Find the call target
            target_node = node.child_by_field_name("function")
            target_text = source_bytes[target_node.start_byte:target_node.end_byte].decode("utf-8", errors="replace").strip() if target_node else ""

            # Check network calls
            is_net = any(
                target_text.startswith(net) or f".{net}." in target_text or target_text.endswith(f".{net}")
                for net in self.NETWORK_MODULES
            ) or ("urlopen" in target_text or "Request" in target_text)

            # Check OS calls
            is_os = False
            if target_text.startswith("os."):
                func_name = target_text.split(".", 1)[1]
                if func_name in self.OS_EXEC_CALLS or func_name == "system" or func_name == "popen":
                    is_os = True
            elif target_text.startswith("subprocess."):
                func_name = target_text.split(".", 1)[1]
                if func_name in self.SUBPROCESS_CALLS:
                    is_os = True
            elif target_text in self.DANGEROUS_BUILTINS:
                is_os = True

            # Get first line of the call
            call_first_line = call_text.splitlines()[0] if call_text else target_text
            if len(call_first_line) > 120:
                call_first_line = call_first_line[:117] + "..."

            if is_net:
                artifacts.append(
                    HighRiskArtifact(
                        category="NETWORK_CALL",
                        source_file=rel_path,
                        line_number=node.start_point.row + 1,
                        raw_code=call_first_line,
                        risk_level="CRITICAL" if "environ" in call_text or "token" in call_text.lower() else "HIGH",
                        details=f"Outbound network invocation: {target_text}",
                    )
                )
            elif is_os:
                artifacts.append(
                    HighRiskArtifact(
                        category="OS_CALL",
                        source_file=rel_path,
                        line_number=node.start_point.row + 1,
                        raw_code=call_first_line,
                        risk_level="CRITICAL" if any(x in target_text for x in ["eval", "exec", "system", "Popen"]) else "HIGH",
                        details=f"OS or process execution invocation: {target_text}",
                    )
                )

        return artifacts

    def extract_from_directory(self, dir_path: Path) -> ASTExtractionResult:
        """Scan all .py files in a directory and collect high-risk AST nodes."""
        result = ASTExtractionResult()
        if not dir_path.exists():
            return result

        py_files = sorted(dir_path.glob("**/*.py")) if dir_path.is_dir() else ([dir_path] if dir_path.suffix == ".py" else [])

        for py_file in py_files:
            result.files_scanned.append(py_file.name)
            file_artifacts = self.extract_from_file(py_file)
            for art in file_artifacts:
                if art.category == "IMPORT":
                    result.imports.append(art)
                elif art.category == "FUNCTION_DEF":
                    result.functions.append(art)
                elif art.category == "NETWORK_CALL":
                    result.network_calls.append(art)
                elif art.category == "OS_CALL":
                    result.os_calls.append(art)
                else:
                    result.other_risks.append(art)

        return result

