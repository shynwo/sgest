"""Rétro-compatibilité : les routes vivent dans ``sgest.views``."""
from __future__ import annotations

from .views import register_routes

__all__ = ["register_routes"]
