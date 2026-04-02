"""
Manufacturer extractor registry.

Each manufacturer package exposes its own ordered EXTRACTORS list.
This registry composes them in inter-manufacturer priority order —
first match wins when a binary is submitted.

Adding a new manufacturer:
    1. Create src/openremap/tuning/manufacturers/<brand>/
    2. Implement extractors — subclass BaseManufacturerExtractor
    3. Expose EXTRACTORS: list[BaseManufacturerExtractor] in <brand>/__init__.py
    4. Import the package here and unpack it into EXTRACTORS below

Inter-manufacturer priority rationale:
    Bosch first   — largest family count (18 extractors), strongest positive
                    signatures (ZZ markers, TSW strings, 1037/0261 part numbers).
    Siemens       — 6 extractors with strong 5WK9 / PPD / SID signatures that
                    are disjoint from Bosch.
    Delphi        — DEL header, HC12 pointer tables, GM part numbers.
                    Must run after Siemens because Multec S shares the 128 KB
                    size with Siemens Simtec 56 (Simtec 56 excludes non-Siemens
                    files, but ordering adds defence-in-depth).
    Marelli       — IAW / MJD families with AA55CC33 sync markers, MAG prefix,
                    byte-swapped AMERLL strings.  Runs last among the currently
                    implemented manufacturers because several Marelli extractors
                    use weaker heuristics (e.g. IAW 1AP has only a 3-byte "1ap"
                    anchor).
"""

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from openremap.tuning.manufacturers import bosch
from openremap.tuning.manufacturers import siemens
from openremap.tuning.manufacturers import delphi
from openremap.tuning.manufacturers import marelli

# ---------------------------------------------------------------------------
# Registry — inter-manufacturer order.
# Intra-manufacturer order is owned by each brand package.
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    *bosch.EXTRACTORS,
    *siemens.EXTRACTORS,
    *delphi.EXTRACTORS,
    *marelli.EXTRACTORS,
    # *denso.EXTRACTORS,
    # *continental.EXTRACTORS,
]

__all__ = ["EXTRACTORS", "BaseManufacturerExtractor"]
