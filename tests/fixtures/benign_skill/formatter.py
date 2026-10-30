import json
import re
from typing import Any, Dict


def format_json_string(raw_content: str, indent: int = 2) -> str:
    """Format and sort keys in a JSON string."""
    try:
        data: Dict[str, Any] = json.loads(raw_content)
        return json.dumps(data, indent=indent, sort_keys=True)
    except json.JSONDecodeError as err:
        return f"Error parsing JSON: {err}"


def sanitize_key_names(raw_content: str) -> str:
    """Strip illegal characters from json property keys."""
    return re.sub(r'[^\w\s-]', '', raw_content)

