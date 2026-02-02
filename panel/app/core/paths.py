from __future__ import annotations

from pathlib import Path

# Directory layout:
#   panel/
#     app/
#       core/paths.py  <- this file
#     templates/
#     static/
#
# We want BASE_DIR to point to the "panel" directory.
BASE_DIR: Path = Path(__file__).resolve().parents[2]
TEMPLATES_DIR: Path = BASE_DIR / "templates"
STATIC_DIR: Path = BASE_DIR / "static"
