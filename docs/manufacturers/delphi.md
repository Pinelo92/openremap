# Supported Delphi ECU Families

The registry currently covers **2 families** of Delphi engine-management ECUs. Originally produced by Delco Electronics (a division of General Motors), later marketed under the Delphi brand following the 1999 spin-off from GM. Common in Opel/Vauxhall vehicles from the late 1990s through mid-2000s.

The registry is designed to be extended — new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

---

## Family reference

| Family | Era | File sizes | Vehicles & applications |
|---|---|---|---|
| **Multec** | 1998–2006 | 208–256 KB | Opel/Vauxhall diesel — 1.7 DTI/TD (Y17DIT, Y17DT engines). Motorola 68k CPU32. |
| **Multec S** | 1996–2003 | 128 KB | Opel/Vauxhall petrol — Astra G, Corsa B/C, Vectra B, Zafira A. HC12/HCS12 CPU. Engines: X16SZR, X14XE, Z16SE, Z14XE. |

---

## Confidence scoring

Every identification result includes a confidence tier so you know how much to trust the match. A **High** result means the file has strong, unambiguous identification signals; a **Low** or **Suspicious** result means you should double-check before relying on it.

| Tier | Meaning |
|---|---|
| **High** | File looks factory-fresh — strong identification signals present |
| **Medium** | Identified with reasonable certainty — some signals missing |
| **Low** | Partial identification — treat with caution |
| **Suspicious** | Signals conflict or appear tampered — inspect manually |
| **Unknown** | No extractor matched — file may not be a supported ECU binary |

For a full breakdown of how scores are calculated, see [Confidence Scoring](../confidence.md).

---

## Adding a new family

The registry is designed so new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for a step-by-step guide.

---

← [Back to README](../../README.md)