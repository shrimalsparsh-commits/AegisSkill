# AegisSkill 🛡️

> **The AST-Aware Security Harness & Supply-Chain Firewall for AI Agent Skills**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests: Passing](https://img.shields.io/badge/tests-9%2F9%20passing-brightgreen.svg)](tests/)

**AegisSkill** is a local Command Line Interface (CLI) security harness and static-to-semantic audit tool designed to protect developers and multi-agent platforms from malicious AI Agent Skills. It specifically targets **"Skill-Inject" supply chain attacks**—such as hidden environment variable harvesting, unauthorized HTTP exfiltration, stealth backdoors, credential theft, and destructive I/O.

---

## ⚡ The Threat: What is a "Skill-Inject" Attack?

Modern agent frameworks (e.g., Claude Code, Cursor, AutoGPT, LangChain, CrewAI) dynamically discover and load third-party "Skills" or tool bundles. However, bad actors can disguise malicious payloads inside helper scripts:

* **The Stated Intent (`SKILL.md`)**: Claims to be *"A benign JSON formatter and validator"*.
* **The Hidden Reality (`helper.py`)**: Contains an AST invocation harvesting `os.environ` secrets and dispatching them via an unlogged `urllib.request.urlopen` POST request to an external command-and-control (C2) server.

**AegisSkill isolates this discrepancy locally—without sending proprietary code to cloud APIs and without blowing past context windows.**

---

## 🏗️ Architecture & Workflow

```mermaid
flowchart TD
    A["Target Skill Directory<br/>(e.g., ./my-skill)"] --> B["YAML Parser<br/>(SKILL.md Frontmatter & Docs)"]
    A --> C["Tree-Sitter AST Parser<br/>(Deterministic Code Analysis)"]
    B --> D["Stated Intent Context<br/>(Declared Capabilities)"]
    C --> E["Extracted High-Risk AST Nodes<br/>- Network Calls (urllib, requests)<br/>- OS & Subprocess Executions<br/>- Credential / os.environ Access"]
    D --> F["Condensed Context Builder<br/>(Strict &lt;= 2048 Token Budget)"]
    E --> F
    F --> G["Local GGUF LLM Engine<br/>(Qwen3 8B / Gemma 3 / Qwen 1.5B via llama-cpp-python)"]
    G --> H["Pydantic JSON Schema Enforcement<br/>{is_safe, threat_category, vulnerability_explanation}"]
    H --> I{"Security Clearance"}
    I -->|Safe| J["✅ PASS (Exit Code 0)<br/>Skill Cleared for Execution"]
    I -->|Threat Detected| K["🚨 BLOCKED (Exit Code 1)<br/>Execution Quarantined"]
```

* **Deterministic AST Extraction**: Full source code is never dumped into the LLM. Tree-sitter isolates only high-risk constructs (network calls, OS/process invocations, os.environ reads, and imports).
* **Context Budget Enforcement**: Guarantees a compact prompt under 2048 tokens (`n_ctx=2048`), ensuring zero VRAM exhaustion on 6GB developer laptops.
* **Structured Pydantic Output**: Strictly enforces JSON grammar validation through `llama.cpp` and outlines.
* **Zero Cloud Leaks**: 100% offline, local-first inference.

---

## 📦 Installation

### Option 1: Install from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/aegisskill.git
cd aegisskill

# Install in editable mode
pip install -e .
```

### Option 2: Pre-compiled Standalone Executable (`aegis.exe`)

Build a single-file, self-contained Windows executable with bundled Tree-sitter and `llama.cpp` runtimes:

```bash
# Build standalone binary
python scripts/build_exe.py

# Test compiled binary
.\dist\aegis.exe --help
```

---

## 🧠 Model Weights & Dynamic Resolution

> **Important**: Model weights (`.gguf` files) are multi-gigabyte binaries and are **never** committed to this repository. Users download their preferred GGUF models externally from sources such as Hugging Face.

### Supported Model Profiles

* **Default (Standard Workstations / GPUs)**: Qwen3 8B, Qwen 2.5 Coder 7B, or Gemma 3
* **Fast Profile (`--fast` for Weak Laptops)**: `qwen2.5-coder-1.5b-instruct-q4_k_m.gguf` (~1 GB VRAM)

### Configure Active Model with `aegis setup`

Use the built-in `setup` command to link your downloaded model into your persistent global directory (`~/.aegisskill/models/active_model.gguf`) using efficient zero-copy hardlinks/symlinks:

```bash
aegis setup --path path/to/your/model.gguf
```

Once configured, all future `aegis scan` runs will automatically use this model without requiring extra flags!

---

## 🚀 CLI Usage

### 1. Audit an Agent Skill (Auto-resolves Active Model)

```bash
aegis scan ./my-agent-skill
```

### 2. Fast Profile for Low-Spec Hardware

```bash
aegis scan ./my-agent-skill --fast
```

### 3. Explicit Custom Model Path

```bash
aegis scan ./my-agent-skill --model-path /path/to/custom-model.gguf
```

### 4. Hackathon / Offline CI Mock Mode (`--dry-run-mock`)

Instantly evaluates skills deterministically with 0.00s latency (ideal for automated CI/CD pipelines):

```bash
aegis scan tests/fixtures/malicious_skill --dry-run-mock
```

### 5. Detailed Verbose Audit Context

```bash
aegis scan ./my-agent-skill --verbose
```

---

## 🧪 Running Automated Tests

Run the complete test suite:

```bash
pytest tests/ -v
```

### Test Coverage Includes:

* Tree-sitter query extraction against benign and malicious test fixtures
* `SKILL.md` YAML frontmatter parsing
* Pydantic schema validation & serialization
* Dynamic model path resolution & `aegis setup`
* CLI exit codes (`0` for PASS, `1` for BLOCKED)

---

## 🔒 Security Threat Categories

| Category | Description |
| :--- | :--- |
| `None` | Verified safe. All AST nodes strictly align with stated utility purpose. |
| `Data Exfiltration` | Harvesting sensitive files or environment variables followed by network dispatch. |
| `Credential Theft` | Unauthorized access to `os.environ`, tokens, SSH keys, or cloud credentials. |
| `Destructive I/O` | Unsafe disk manipulation (e.g., `rm -rf`, `shutil.rmtree`, file overwrites). |
| `Arbitrary Code Execution` | Dynamic shell commands, `subprocess`, `os.system`, or `eval`. |
| `Skill-Inject Supply Chain Attack` | Severe mismatch between documented skill purpose and underlying executable logic. |

---

## 📄 License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
