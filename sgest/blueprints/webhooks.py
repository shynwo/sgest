"""Webhooks commandes (Etsy, Vinted)."""
from __future__ import annotations

from flask import Blueprint

from ..services import *  # noqa: F401,F403


bp = Blueprint("webhooks", __name__)

@bp.post("/webhooks/orders/etsy")
def webhook_orders_etsy():
    return _webhook_receive("etsy")


@bp.post("/webhooks/orders/vinted")
def webhook_orders_vinted():
    return _webhook_receive("vinted")
