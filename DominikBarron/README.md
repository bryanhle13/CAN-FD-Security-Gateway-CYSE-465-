# CAN-FD Flooding Attack & Defensive Gateway Demo
This project demonstrates how a high-priority flooding attack (DoS) on a CAN-style bus can suppress legitimate traffic, and how a defensive gateway can partially mitigate the attack using per-ID rate-limiting and semantic validation.

The demo includes:
- **can_fd_attack_flood_dos.py** – simulates an attacker flooding the CAN bus.
- **can_fd_defense_fair_gateway.py** – an improved gateway that distinguishes trusted vs untrusted IDs and rate-limits malicious traffic.

Both scripts use the `python-can` virtual interface to simulate traffic on a shared bus called `"demo"`.

---

## Overview

Modern vehicles rely on CAN buses for intra-vehicle communication. CAN arbitration gives priority to lower numeric IDs. Attackers can exploit this by sending **high-priority (low ID)** frames continuously, starving legitimate ECUs of bus time and causing a **Denial-of-Service attack**.

This project demonstrates:

### 1. **Attack Scenario**
- A legitimate ECU sends engine telemetry on **ID 0x200**.
- An attacker floods the bus with high-priority frames on **ID 0x001**.
- The insecure receiver shows how attack frames dominate the bus.

### 2. **Defense Scenario**
- A simulated gateway monitors incoming CAN frames.
- It enforces **per-ID rate limits** and **basic semantic checks**.
- Legitimate traffic (ID 0x200) is treated differently from untrusted or unknown IDs.
- Flooding traffic is blocked once it exceeds its allowed rate.

---

## 📁 File Descriptions

### **`can_fd_attack_flood_dos.py`**
Demonstrates a pure attack environment without defensive controls.

Key behaviors:
- Legitimate sender transmits engine RPM/temp/fuel at a fixed rate.
- Attacker floods ID `0x001` at ~50 messages/sec.
- Receiver shows that legitimate messages are starved due to CAN arbitration unfairness.

### **`can_fd_defense_fair_gateway.py`**
Implements a more realistic gateway defense:

**Enhancements over the naive "fast = bad" heuristic include:**
- **Per-ID policies** (`PER_ID_POLICY`):
  - Trusted IDs can transmit at higher rates.
  - Untrusted IDs have stricter limits.
- **Semantic validation**:
  - RPM, coolant temp, and fuel levels must fall within plausible ranges.
- **Clear logging** for forwarded vs blocked traffic.
- **Default policies** for unknown IDs.

This helps address weaknesses such as:
- False positives on high-rate legitimate traffic.
- Attacker exploiting rate-limit logic to deny specific ECUs.
- Lack of contextual interpretation of message content.

---

## 🚀 Running the Demo

### Prerequisites
Install python-can:

```bash
pip install python-can
