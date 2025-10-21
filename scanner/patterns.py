import re
import yaml
import sys
import logging
from dataclasses import dataclass, field
from typing import List, Optional

# Set up a logger for this module
logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class Pattern:
    """
    A dataclass representing a single, compiled secret detection rule.

    This object is immutable (frozen) to prevent runtime modifications,
    which is a best practice for shared configuration objects.
    
    Attributes:
        rule_id (str): A unique identifier for the rule (e.g., "AWS-001").
        description (str): A human-readable description of the secret.
        regex (re.Pattern): The compiled regular expression for detection.
        confidence (str): The scanner's confidence in this pattern 
                          (e.g., 'High', 'Medium', 'Low').
        entropy_threshold (float): The minimum Shannon entropy required to 
                                   consider a match valid. 0.0 disables it.
        keywords (List[str]): Optional keywords to look for near the match
                              to increase confidence (not yet implemented in core).
        secret_type (Optional[str]): The category for the validation service 
                                     (e.g., 'AWS', 'GitHub', 'Stripe').
        validation_enabled (bool): Whether this secret type should be sent to 
                                   the validation service.
    """
    rule_id: str
    description: str
    regex: re.Pattern
    confidence: str
    
    # Optional advanced fields
    entropy_threshold: float = 0.0
    keywords: List[str] = field(default_factory=list)
    
    # Phase 4 Validation fields
    secret_type: Optional[str] = None
    validation_enabled: bool = False

def load_patterns(patterns_file: str) -> List[Pattern]:
    """
    Loads, parses, and compiles all secret patterns from a YAML file.

    This function is designed to be resilient. It will log errors for
    individual invalid patterns but will continue to load all other
    valid patterns.
    
    It will, however, fail catastrophically if the file itself cannot be
    found or parsed, as the scanner cannot operate without rules.

    Args:
        patterns_file: The file path to the `patterns.yml` definition file.

    Returns:
        A list of compiled, immutable Pattern objects.

    Raises:
        FileNotFoundError: If the specified patterns_file does not exist.
        yaml.YAMLError: If the YAML file is malformed and cannot be parsed.
    """
    logger.info(f"Loading patterns from {patterns_file}")
    
    try:
        with open(patterns_file, 'r', encoding='utf-8') as f:
            # Use safe_load to prevent arbitrary code execution from YAML
            patterns_data = yaml.safe_load(f)
            if not patterns_data or 'patterns' not in patterns_data:
                logger.error("Pattern file is empty or missing 'patterns' top-level key.")
                return []
                
    except FileNotFoundError:
        logger.critical(f"FATAL: Pattern file not found at '{patterns_file}'. Cannot proceed.")
        raise  # Re-raise the exception to be caught by the main entry point
    except yaml.YAMLError as e:
        logger.critical(f"FATAL: Error parsing YAML file '{patterns_file}'. {e}")
        raise  # Re-raise the exception

    compiled_patterns: List[Pattern] = []
    
    for p_data in patterns_data.get('patterns', []):
        try:
            # --- 1. Validation ---
            # Ensure all required fields are present
            required_fields = ['rule_id', 'description', 'regex', 'confidence']
            for field_name in required_fields:
                if field_name not in p_data:
                    raise KeyError(f"Missing required field '{field_name}'")

            # --- 2. Compilation ---
            # Compile the regex, the most likely point of failure
            compiled_regex = re.compile(p_data['regex'])

            # --- 3. Object Creation ---
            # Create the immutable Pattern object
            pattern = Pattern(
                rule_id=p_data['rule_id'],
                description=p_data['description'],
                regex=compiled_regex,
                confidence=p_data['confidence'],
                
                # Use .get() for optional fields to provide safe defaults
                entropy_threshold=p_data.get('entropy_threshold', 0.0),
                keywords=p_data.get('keywords', []),
                secret_type=p_data.get('secret_type'),
                validation_enabled=p_data.get('validation_enabled', False)
            )
            
            compiled_patterns.append(pattern)

        except re.error as e:
            # Log a warning for a bad regex but continue loading others
            logger.warning(
                f"Skipping pattern '{p_data.get('rule_id', 'UNKNOWN')}': "
                f"Invalid regex. Error: {e}"
            )
        except KeyError as e:
            # Log a warning for a malformed pattern entry
            logger.warning(
                f"Skipping pattern '{p_data.get('rule_id', 'UNKNOWN')}': "
                f"Configuration error. {e}"
            )
        except Exception as e:
            # Catch any other unexpected errors during pattern creation
            logger.warning(
                f"SkiDELETExiting pattern '{p_data.get('rule_id', 'UNKNOWN')}': "
                f"An unexpected error occurred: {e}"
            )

    logger.info(f"Successfully loaded and compiled {len(compiled_patterns)} patterns.")
    return compiled_patterns
