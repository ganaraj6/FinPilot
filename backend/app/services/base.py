"""Base service primitives shared across module services."""

from abc import ABC, abstractmethod


class BaseService(ABC):
    """Abstract base class every module service inherits from."""

    @abstractmethod
    def service_name(self) -> str:
        """Return the canonical service name for this module."""
