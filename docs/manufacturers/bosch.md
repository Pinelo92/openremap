# Supported Bosch ECU Families

The registry currently covers **19 families** of Bosch engine-management ECUs, spanning from 1982 to the present day. Whether you're working with a classic Volvo LH-Jetronic bin or a modern EDC17 diesel file, this page tells you what's supported and at what confidence level.

The registry is designed to be extended — new manufacturers and families can be added without touching existing code. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

---

## Family reference

| Family | Era | File sizes | Vehicles & applications |
|---|---|---|---|
| **EDC1 / EDC2** | 1990–1997 | 32–64 KB | Audi 80/A6 TDI, early common-rail diesel |
| **EDC 3.x** | 1993–2000 | 128–512 KB | VAG TDI, BMW diesel, Opel diesel |
| **EDC15** | 1997–2004 | 512 KB | VAG, Fiat, Volvo, BMW diesel |
| **EDC16** | 2003–2008 | 256 KB–2 MB | VAG PD/CR TDI, BMW diesel, Opel/GM diesel |
| **EDC17 / MEDC17 / MED17 / ME17 / MD1** | 2008–present | 2–8 MB | VAG, BMW, Mercedes, PSA diesel and petrol |
| **ME7** | 1997–2008 | 64 KB–1 MB | VAG 1.8T, Porsche, Ferrari, Opel (sub-families ME7.1 through ME7.6.2) |
| **ME9** | 2001–2006 | 2 MB | VW/Audi 1.8T 20v full flash |
| **MED9** | 2002–2008 | 512 KB–2 MB | VAG FSI and TFSI petrol direct injection |
| **M1.x** | 1987–1996 | 32–64 KB | BMW E28/E30/E34/E36, Opel petrol |
| **M1.55 / M1.5.5** | 1994–2002 | 128 KB | Alfa Romeo 155/156/GT, Opel Corsa C/Astra G |
| **M2.x** | 1993–1999 | 32–128 KB | VW/Audi, Porsche 964, Opel |
| **M3.x** | 1989–1999 | 32–256 KB | BMW E30/E36 petrol, PSA/Citroën petrol |
| **M4.x** | 1994–2002 | 64–128 KB | Volvo 850/960/S70/V70/S60/S80 petrol |
| **M5.x / M3.8x** | 1997–2004 | 128–256 KB | VW/Audi 1.8T (AGU, AUM, APX) |
| **MP9** | 1996–2002 | 64 KB | VW/Seat/Skoda 1.0–1.6L petrol |
| **Mono-Motronic** | 1991–1999 | 32–64 KB | VW/Audi/Skoda/Seat 1.0–1.6L single-point injection |
| **ME1.5.5** | 1998–2004 | 128 KB–256 KB | Alfa Romeo, Fiat petrol |
| **LH-Jetronic** | 1982–1995 | 8–64 KB | Volvo, early BMW and Mercedes fuel injection |
| **Motronic Legacy** | various | 2–32 KB | Porsche 911 DME-3.2, BMW E30/M3, KE-Jetronic, EZK ignition |

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

## Technical reference

For extractor internals, detection strategies, and OEM-specific format notes, see [Bosch Internals](bosch-internals.md).

---

← [Back to README](../../README.md)