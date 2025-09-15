from typing import Dict, Any
from copy import deepcopy

def mutate_field(base: Dict[str, Any], field_path: str, value: Any) -> Dict[str, Any]:
    """
    Return a mutated copy of `base` where `field_path` (dot notation) is set to `value`.
    
    Args:
        base: The base dictionary to modify
        field_path: Dot-notation path to the field (e.g. "user.address.street")
        value: The value to set at the specified path
    
    Returns:
        A new dictionary with the specified field modified
    
    Example:
        >>> data = {"user": {"name": "John", "age": 30}}
        >>> mutate_field(data, "user.age", 31)
        {'user': {'name': 'John', 'age': 31}}
    """
    p = deepcopy(base)
    parts = field_path.split(".")
    cur = p
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value
    return p
