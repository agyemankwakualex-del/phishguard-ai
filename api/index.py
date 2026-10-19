"""Vercel serverless entry. Local `python app.py` and the Procfile stay as they are."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root = str(ROOT)
if root not in sys.path:
    sys.path.insert(0, root)

# The project directory is not a durable disk on Vercel. /tmp lasts for one instance.
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite:////tmp/phishguard.db"

from app import app  # noqa: E402
