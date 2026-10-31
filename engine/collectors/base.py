"""Collector interface. Collectors are read-only and never judge compliance."""

from __future__ import annotations

import logging
import socket
from abc import ABC, abstractmethod

from ..models import CollectionError, Evidence


class Collector(ABC):
    name = "collector"
    version = "1"
    evidence_type = ""
    ttl_hours = 24.0

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def asset_id(self) -> str:
        return self.config.get("asset_id") or socket.gethostname()

    @abstractmethod
    def gather(self) -> dict:
        """Return the raw evidence payload. Raise on any failure."""

    def collect(self) -> tuple[list[Evidence], list[CollectionError]]:
        try:
            payload = self.gather()
        except Exception as exc:  # unreachable host, expired creds, missing tool...
            self.logger.warning("%s failed: %s", self.name, exc)
            return [], [CollectionError(self.name, self.evidence_type, str(exc), self.asset_id)]
        return [
            Evidence(
                type=self.evidence_type,
                asset_id=self.asset_id,
                collector=self.name,
                collector_version=self.version,
                payload=payload,
                ttl_hours=self.ttl_hours,
            )
        ], []
