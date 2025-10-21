# scanner/patterns.py
import re
from dataclasses import dataclass
from typing import List
import yaml

@dataclass(frozen=True)
class Pattern:
    """A dataclass to represent a secret pattern to be scanned for."""
    rule_id: str
    description: str
    regex: re.Pattern
    confidence: str

def load_patterns(file_path: str) -> List[Pattern]:
    """
    Loads and compiles regex patterns from a YAML file.

    Args:
        file_path: The path to the patterns.yml file.

    Returns:
        A list of compiled Pattern objects.

    Raises:
        FileNotFoundError: If the patterns file does not exist.
        yaml.YAMLError: If the YAML is malformed.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_patterns = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Pattern file not found at '{file_path}'")
        raise
    except yaml.YAMLError as e:
        print(f"Error: Could not parse YAML file: {e}")
        raise

    compiled_patterns = []
    for p in raw_patterns:
        try:
            compiled_patterns.append(
                Pattern(
                    rule_id=p['rule_id'],
                    description=p['description'],
                    regex=re.compile(p['regex']),
                    confidence=p['confidence']
                )
            )
        except re.error as e:
            print(f"Warning: Invalid regex in rule {p.get('rule_id', 'unknown')}: {e}")
            continue

    return compiled_patterns
