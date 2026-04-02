# Supported Magneti Marelli ECU Families

The registry currently covers **4 families** of Magneti Marelli engine-management ECUs. Magneti Marelli (now MARELLI) is an Italian manufacturer that has supplied ECUs primarily to European OEMs — VAG (VW, Skoda, Seat), PSA (Peugeot, Citroën), Fiat, and GM/Opel.

The registry is designed to be extended — new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

---

## Family reference

| Family | Era | File sizes | Vehicles & applications |
|---|---|---|---|
| **IAW 1AV** | 1996–2003 | 64 KB | VAG — Skoda, VW, Seat 1.0–1.6L NA petrol. Contains `MARELLI` and `iaw1av` ASCII strings. |
| **IAW 1AP** | 1996–2002 | 64 KB | PSA — Peugeot 106/206, Citroën Saxo/C3 1.0–1.4i petrol. ST6 microcontroller. Extremely sparse binary — no `MARELLI` string embedded. |
| **IAW 4LV** | 2000s | 512 KB | VAG — Skoda Fabia 1.4 16V 100HP, VW, Seat. Motorola 68332/68336 (M68K). Notable for byte-swapped ASCII strings. |
| **MJD 6JF** | 2006–2015 | 448–452 KB | GM/Opel/Vauxhall Corsa D/E 1.3 CDTI diesel (UZ13DT engine). PowerPC CPU. |

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

> **Note on sparse architectures:** Some Marelli families — notably **IAW 1AP** — produce binaries with almost no embedded metadata. IAW 1AP contains only a lowercase `"1ap"` tag and a calibration fingerprint. These sparse binaries will produce **Low** or **Medium** confidence scores even for genuine, untouched files. The confidence system accounts for this by not penalising the absence of fields that the family architecture does not store.

For a full breakdown of how scores are calculated, see [Confidence Scoring](../confidence.md).

---

## Adding a new family

The registry is designed so new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for a step-by-step guide.

---

← [Back to README](../../README.md)