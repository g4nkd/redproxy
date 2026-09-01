"""Target plugins for redproxy sprayer."""
from .base import TargetPlugin
from .microsoft import MicrosoftTarget
from .custom import CustomTarget

TARGETS = {
    "microsoft": MicrosoftTarget,
    "custom": CustomTarget,
}


def get_target(name: str):
    """Get a target plugin by name."""
    if name not in TARGETS:
        raise ValueError(f"Unknown target: {name}. Available: {', '.join(TARGETS.keys())}")
    return TARGETS[name]
