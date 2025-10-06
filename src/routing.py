from typing import Optional

BROADCAST = "*"

def is_broadcast(to_field: Optional[str]) -> bool:
    return (to_field is None) or (to_field == BROADCAST)
