"""Offline synthetic boot-attestation audit service.

Package layout
--------------
``crypto``      deterministic synthetic signatures and the SHA-256 chain
``baselines``   baseline document validation, publication and eligibility
``verify``      stateless attestation verification (outside any transaction)
``store``       SQLite schema, connections, units of work and kill points
``service``     protocol operations, transactional commit, receipts
``synthetic``   fixture builders used by ``cases.json`` and the tests
``runner``      replay engine for ``cases.json``
``worker``      separate-process verification entry point
"""

from __future__ import annotations

__version__ = "1.0.0"

from .errors import ERROR_CODES, Denial  # noqa: F401
from .service import execute_operation  # noqa: F401

__all__ = ["ERROR_CODES", "Denial", "execute_operation", "__version__"]
