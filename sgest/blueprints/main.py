"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from flask import Blueprint

from ..services import *  # noqa: F401,F403


bp = Blueprint("main", __name__)

@bp.get("/ping")
def ping(): return jsonify(ok=True, t=int(time.time()))
@bp.route("/")
def dashboard():
    bro = _dashboard_stock_summary("broderie")
    impr = _dashboard_stock_summary("impression3d")
    stocks = [bro, impr]
    biz = _biz_totals()

    return render_template(
        "index.html",
        title="Dashboard",
        stocks=stocks,
        total_refs=bro["refs"] + impr["refs"],
        total_units=round(float(bro["units"]) + float(impr["units"]), 3),
        total_low_alerts=bro["low_count"] + impr["low_count"],
        total_gain=biz["profit"],
        total_sales=biz["sale_count"],
    )
