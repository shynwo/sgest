"""Requêtes SQLite réutilisables — stock broderie / impression 3D."""

# --- Pages liste + filtres -------------------------------------------------

BRO_PAGE_ITEMS = (
    "SELECT i.id, i.material, i.color, i.ref, i.price, i.qty, "
    "COALESCE(i.name,'') AS name, COALESCE(a.threshold,0) AS min_qty "
    "FROM stock_bro i "
    "LEFT JOIN stock_bro_alerts a ON a.item_id = i.id "
    "ORDER BY i.id DESC"
)

BRO_DISTINCT_MATERIALS = (
    "SELECT DISTINCT material FROM stock_bro WHERE material IS NOT NULL AND material<>'' ORDER BY 1"
)

BRO_DISTINCT_COLORS = (
    "SELECT DISTINCT color FROM stock_bro WHERE color IS NOT NULL AND color<>'' ORDER BY 1"
)

BRO_DISTINCT_REFS = (
    "SELECT DISTINCT ref FROM stock_bro WHERE ref IS NOT NULL AND TRIM(ref)<>'' ORDER BY 1"
)

BRO_ALERTS_PANEL = (
    "SELECT i.id, COALESCE(i.name,'') AS name, i.material, i.color, i.qty, "
    "COALESCE(a.threshold,0) AS min_qty "
    "FROM stock_bro i JOIN stock_bro_alerts a ON a.item_id = i.id "
    "ORDER BY i.id DESC"
)

THREED_PAGE_ITEMS = (
    "SELECT i.id, i.material, i.color, i.ref, i.price, i.qty, "
    "COALESCE(i.name,'') AS name, COALESCE(a.threshold,0) AS min_qty "
    "FROM stock_3d i "
    "LEFT JOIN stock_3d_alerts a ON a.item_id = i.id "
    "ORDER BY i.id DESC"
)

THREED_DISTINCT_MATERIALS = (
    "SELECT DISTINCT material FROM stock_3d WHERE material IS NOT NULL AND material<>'' ORDER BY 1"
)

THREED_DISTINCT_COLORS = (
    "SELECT DISTINCT color FROM stock_3d WHERE color IS NOT NULL AND color<>'' ORDER BY 1"
)

THREED_ALERTS_PANEL = (
    "SELECT i.id, COALESCE(i.name,'') AS name, i.material, i.color, i.qty, "
    "COALESCE(a.threshold,0) AS min_qty "
    "FROM stock_3d i JOIN stock_3d_alerts a ON a.item_id = i.id "
    "ORDER BY i.id DESC"
)

# --- API alertes (seuils dépassés) ------------------------------------------

BRO_ALERTS_API_ROWS = """
    SELECT b.id,b.name,b.ref,b.material,b.color,b.qty,a.threshold
    FROM stock_bro b
    JOIN stock_bro_alerts a ON a.item_id=b.id
    WHERE a.threshold>0 AND IFNULL(b.qty,0) <= a.threshold
    ORDER BY b.id DESC
"""

# --- Variante / upsert broderie --------------------------------------------

BRO_FIND_VARIANT = """
    SELECT id
    FROM stock_bro
    WHERE ref=? AND COALESCE(material,'')=? AND COALESCE(color,'')=?
    LIMIT 1
"""

BRO_UPDATE_VARIANT_QTY = """
    UPDATE stock_bro
    SET qty = COALESCE(qty,0) + ?,
        price = ?,
        name = CASE WHEN TRIM(?)<>'' THEN ? ELSE name END
    WHERE id=?
"""

BRO_INSERT_ROW = "INSERT INTO stock_bro(name,material,color,ref,price,qty) VALUES (?,?,?,?,?,?)"
