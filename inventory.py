# -*- coding: utf-8 -*-
import sqlite3
from pathlib import Path
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app

inventory_bp = Blueprint('inventory', __name__)

def _con_3d():
    base = Path(current_app.root_path) / 'data'
    base.mkdir(parents=True, exist_ok=True)
    db = base / 'impression3d.db'
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS stock_3d(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            ref  TEXT DEFAULT '',
            material TEXT NOT NULL,
            color TEXT NOT NULL,
            price REAL DEFAULT 0,
            qty   INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    return con

@inventory_bp.route('/stock/impression3d', methods=['GET'])
def inv_3d_page():
    con = _con_3d()
    items = con.execute("""
        SELECT id,name,ref,material,color,price,qty,created_at
        FROM stock_3d
        ORDER BY id DESC
    """).fetchall()
    mats = [r[0] for r in con.execute("SELECT DISTINCT material FROM stock_3d ORDER BY material").fetchall()]
    cols = [r[0] for r in con.execute("SELECT DISTINCT color    FROM stock_3d ORDER BY color").fetchall()]
    con.close()
    return render_template('stock_3D.html', items=items, materials=mats, colors=cols)

@inventory_bp.post('/stock/impression3d/add')
def inv_3d_add():
    name = (request.form.get('name') or '').strip()
    ref  = (request.form.get('ref')  or '').strip()
    material = (request.form.get('material') or request.form.get('material_new') or '').strip()
    color    = (request.form.get('color')    or request.form.get('color_new')    or '').strip()

    def to_float(v, default=0.0):
        try: return float((v or '').replace(',', '.'))
        except: return default
    def to_int(v, default=0):
        try: return int(v or 0)
        except: return default

    price = to_float(request.form.get('price'), 0.0)
    qty   = to_int(request.form.get('qty'),   0)

    if not material or not color or qty <= 0:
        flash("Sélectionne une matière, une couleur et une quantité > 0.", "warning")
        return redirect(url_for('inventory.inv_3d_page'))

    con = _con_3d()
    con.execute(
        "INSERT INTO stock_3d(name,ref,material,color,price,qty) VALUES (?,?,?,?,?,?)",
        (name, ref, material, color, price, qty)
    )
    con.commit()
    con.close()
    flash("Article ajouté.", "success")
    return redirect(url_for('inventory.inv_3d_page'))
