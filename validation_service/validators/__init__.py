import pkgutil
import inspect
from pathlib import Path
from typing import Dict, Type

from .base_validator import BaseValidator

# --- Dynamic Validator Loading and Registry ---

# A global registry to hold all discovered validator classes
# The key is the `secret_type` (e.g., "aws"), value is the class itself.
VALIDATOR_REGISTRY: Dict[str, Type[BaseValidator]] = {}

def discover_and_register_validators():
    """
    Dynamically discovers and imports all validator modules in this package
    and registers any classes that inherit from BaseValidator.
    
    This makes the worker extensible. To add a new validator, you just
    need to drop a new file in this directory.
    """

    if VALIDATOR_REGISTRY: # Ensure this runs only once
        return

    package_path = Path(__file__).parent
    
    for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
        # Import the module
        module = __import__(f"{__name__}.{module_name}", fromlist=["*"])

        # Find any classes in the module that are subclasses of BaseValidator
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, BaseValidator) and obj is not BaseValidator:
                # Use the `secret_type` class attribute as the key
                if hasattr(obj, 'secret_type') and obj.secret_type:
                    VALIDATOR_REGISTRY[obj.secret_type] = obj

# Run discovery on import
discover_and_register_validators()

def get_validator(secret_type: str) -> BaseValidator | None:
    """
    Retrieves an instantiated validator class from the registry.
    """
    validator_class = VALIDATOR_REGISTRY.get(secret_type.lower())
    return validator_class() if validator_class else None

def is_validator_supported(secret_type: str) -> bool:
    """Checks if a validator exists for the given secret type."""
    return secret_type.lower() in VALIDATOR_REGISTRY

def get_supported_validators() -> list:
    """Returns a list of all supported validator types and their descriptions."""
    return [
        {"type": v.secret_type, "description": v.description}
        for v in VALIDATOR_REGISTRY.values()
    ]
