"""Control-ID universe for coverage accounting.

``data/rev5_control_ids.json`` holds only control IDs (no control text) for
NIST SP 800-53 Rev. 5 (catalog 5.2.0) and the Low/Moderate/High baselines,
extracted from NIST's OSCAL content at a pinned commit. ``fetch_catalog``
downloads the full OSCAL catalog from the same commit and verifies its hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from functools import lru_cache

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rev5_control_ids.json")
BASELINES = ("low", "moderate", "high", "all")


@lru_cache(maxsize=1)
def _load() -> dict:
    with open(DATA, "r", encoding="utf-8") as fh:
        return json.load(fh)


def catalog_info() -> dict:
    return _load()["_source"]


def baseline_ids(name: str) -> list[str]:
    if name not in BASELINES:
        raise ValueError(f"unknown baseline {name!r}; expected one of {', '.join(BASELINES)}")
    return list(_load()[name])


def fetch_catalog(dest: str) -> str:
    """Download the pinned full OSCAL catalog to ``dest`` and verify its SHA-256."""
    src = catalog_info()
    meta = src["files"]["catalog"]
    url = f"https://raw.githubusercontent.com/usnistgov/oscal-content/{src['commit']}/{src['path']}/{meta['name']}"
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https URL
        body = resp.read()
    digest = hashlib.sha256(body).hexdigest()
    if digest != meta["sha256"]:
        raise ValueError(f"catalog hash mismatch: expected {meta['sha256']}, got {digest}")
    with open(dest, "wb") as fh:
        fh.write(body)
    return dest
