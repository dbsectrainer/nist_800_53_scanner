"""Collector interface. Collectors are read-only and never judge compliance."""

from __future__ import annotations

import logging
import socket
from abc import ABC

from ..models import CollectionError, Evidence


class Collector(ABC):
    name = "collector"
    version = "1"
    evidence_type = ""
    method = "examine"  # NIST SP 800-53A assessment method for this evidence
    ttl_hours = 24.0

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.partial_errors = []
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def asset_id(self) -> str:
        return self.config.get("asset_id") or socket.gethostname()

    def gather(self) -> dict:
        """Return the raw evidence payload for one asset. Raise on any failure."""
        raise NotImplementedError

    def gather_assets(self) -> list[tuple[str, dict]]:
        """Return ``[(asset_id, payload)]``. Override for collectors spanning several assets.

        Append to ``self.partial_errors`` for assets that fail while others succeed.
        """
        return [(self.asset_id, self.gather())]

    def collect(self) -> tuple[list[Evidence], list[CollectionError]]:
        self.partial_errors: list[CollectionError] = []
        try:
            items = self.gather_assets()
        except Exception as exc:  # unreachable host, expired creds, missing tool...
            self.logger.warning("%s failed: %s", self.name, exc)
            return [], [CollectionError(self.name, self.evidence_type, str(exc), self.asset_id), *self.partial_errors]
        evidence = [
            Evidence(
                type=self.evidence_type,
                asset_id=asset_id,
                collector=self.name,
                collector_version=self.version,
                method=self.method,
                payload=payload,
                ttl_hours=self.ttl_hours,
            )
            for asset_id, payload in items
        ]
        return evidence, list(self.partial_errors)
