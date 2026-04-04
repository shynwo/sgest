"""Point d'entrée WSGI (Gunicorn : ``app:app``). La logique vit dans le package ``sgest``."""
from sgest.factory import create_app

app = create_app()
