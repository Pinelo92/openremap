# Supported Siemens ECU Families

The registry currently covers **6 families** of Siemens engine-management ECUs, spanning from 1995 to 2010. These ECUs were originally produced by Siemens Automotive and later marketed under the Siemens VDO and Continental brands following the 2007 acquisition — you may see any of these names used interchangeably in the tuning community.

The registry is designed to be extended — new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

---

## Family reference

| Family | Era | File sizes | Vehicles & applications |
|---|---|---|---|
| **Simtec 56** | 1995–2002 | 128 KB | Opel/Vauxhall Vectra B, Astra, Omega B, Calibra (X18XE, X20XEV engines) |
| **SIMOS** | 1998–2006 | 131 KB, 262 KB, 524 KB | VW/Audi/Skoda/Seat 1.4–1.6L petrol (Golf 4, Bora, Beetle, Fabia, Octavia, Leon) |
| **PPD1.x** | 2003–2008 | 250 KB – 2 MB | VW/Audi/Skoda/Seat 2.0 TDI Pumpe-Düse diesel (PPD1.1, PPD1.2, PPD1.5) |
| **SID 801 / SID 801A** | 2001–2006 | 512 KB | Peugeot/Citroën 2.0/2.2 HDi diesel (307, 406, Partner) |
| **SID 803 / SID 803A** | 2005–2010 | 458 KB – 2 MB | Peugeot/Citroën 2.0/2.2 HDi diesel (407, 607, C5) |
| **EMS2000** | 1996–2004 | 256 KB | Volvo S40/V40/S60/S70/V70 T4/T5 turbo petrol |

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

> **Note on "dark" bins:** Some Siemens families — notably **SIMOS** and **EMS2000** — produce bins with minimal embedded metadata (no clear ASCII part numbers, no obvious calibration ID strings). These "dark" bins make fingerprinting harder, so expect confidence scores to trend toward **Medium** or **Low** even for genuine, untouched files. The extractors compensate by relying more heavily on file-size heuristics and binary structure patterns, but the reduced signal density means there is less room for a **High** confidence match compared to more verbose families like PPD1.x or SID 80x.

For a full breakdown of how scores are calculated, see [Confidence Scoring](../confidence.md).

---

## Adding a new family

The registry is designed so new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for a step-by-step guide.

---

## Technical reference

For extractor internals, detection strategies, and OEM-specific format notes, see [Siemens Internals](siemens-internals.md).

---

← [Back to README](../../README.md)