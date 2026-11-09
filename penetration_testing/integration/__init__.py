"""Integration layer: discover and safely invoke existing ARTEX modules."""

from .module_bridge import ModuleBridge, CapabilitySpec

__all__ = ["ModuleBridge", "CapabilitySpec"]
