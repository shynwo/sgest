"""Rétro-compatibilité : les routes sont des blueprints dans ``sgest.blueprints``."""
from __future__ import annotations

from .blueprints import register_blueprints as register_routes

__all__ = ["register_routes"]
