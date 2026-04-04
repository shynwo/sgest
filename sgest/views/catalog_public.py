"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from ..services import *  # noqa: F401,F403


def register_catalog_public_routes(app) -> None:
    @app.get("/catalogue/public/<token>")
    def catalog_public_page(token: str):
        con = _con_biz()
        try:
            cat = con.execute("""
                SELECT * FROM catalogs
                WHERE public_token=? AND is_public=1
                LIMIT 1
            """, (token,)).fetchone()
            if not cat:
                abort(404)
            catalog = dict(cat)
        finally:
            con.close()

        items = _catalog_items_with_files(int(catalog["id"]))
        return render_template("catalog_public.html", title=f"Catalogue {catalog['name']}", catalog=catalog, items=items)
    @app.get("/catalogue/public/<token>/files/<int:file_id>")
    def catalog_public_file(token: str, file_id: int):
        con = _con_biz()
        try:
            row = con.execute("""
                SELECT f.*
                FROM catalog_files f
                JOIN catalogs c ON c.id = f.catalog_id
                WHERE f.id=? AND c.public_token=? AND c.is_public=1
                LIMIT 1
            """, (file_id, token)).fetchone()
        finally:
            con.close()
        if not row:
            abort(404)
        abs_path = _catalog_file_abs_path(row["file_name"])
        if not abs_path or not os.path.isfile(abs_path):
            abort(404)
        return send_file(abs_path, as_attachment=False, download_name=row["original_name"])
