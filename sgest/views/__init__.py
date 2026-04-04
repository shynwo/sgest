"""Enregistrement de toutes les routes (ordre = ancien monolithe)."""
from __future__ import annotations

from .auth import register_auth_routes
from .catalog_public import register_catalog_public_routes
from .main import register_main_routes
from .stock import register_stock_routes
from .system import register_system_routes
from .tools import register_tools_routes


def register_routes(app) -> None:
    """Attache les vues ; noms d'endpoints inchangés."""
    register_auth_routes(app)
    register_main_routes(app)
    register_tools_routes(app)
    register_catalog_public_routes(app)
    register_system_routes(app)
    register_stock_routes(app)
